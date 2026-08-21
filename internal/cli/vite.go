package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// viteStartup bounds how long the dev server may take to answer. A cold start
// has to transform the dependency graph, so this is generous — but not
// unbounded, because a Vite that will never come up must not leave `serve`
// waiting forever with nothing on the port.
const viteStartup = 90 * time.Second

// startVite runs the app's Vite dev server on a free port and returns where it
// is listening, along with the function that stops it.
//
// The port is chosen rather than fixed so several checkouts can serve at once:
// the app pins 5280 with strictPort, which makes a second instance fail outright
// instead of picking another. Nothing has to know the number — the API server
// proxies to it, so the browser only ever sees the address `serve` printed.
//
// Stopping is the caller's to defer rather than something cancelling the context
// takes care of: `serve` can return without the context ever being cancelled,
// and a Vite left holding a port after its parent exited is invisible until the
// next run fails to bind.
func startVite(ctx context.Context, out io.Writer) (*url.URL, func(), error) {
	dir, err := appDir()
	if err != nil {
		return nil, nil, err
	}
	if _, err := exec.LookPath("pnpm"); err != nil {
		return nil, nil, fmt.Errorf("--dev needs pnpm on PATH to run the Vite dev server: %w", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); err != nil {
		return nil, nil, fmt.Errorf("--dev needs the app's dependencies: run `pnpm install` in %s", dir)
	}

	port, err := freePort()
	if err != nil {
		return nil, nil, err
	}

	// Killing the process group, not the process: pnpm execs node, and signalling
	// only the parent leaves Vite holding the port after `serve` exits.
	// --host is pinned rather than left to resolve: Vite's default binds the
	// loopback name, which lands on ::1, and the proxy would then be dialling a
	// v4 address nothing is listening on.
	command := exec.CommandContext(ctx, "pnpm", "--dir", dir, "exec", "vite",
		"--host", "127.0.0.1", "--port", strconv.Itoa(port), "--strictPort")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	command.Stdout, command.Stderr = out, out

	if err := command.Start(); err != nil {
		return nil, nil, fmt.Errorf("start vite: %w", err)
	}

	// Reaped rather than left as a zombie, and it also releases WaitDelay's kill.
	exited := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(exited)
	}()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			if command.Process == nil {
				return
			}
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			}
		})
	}

	target := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	if err := waitForVite(ctx, target); err != nil {
		// A Vite that came up but was not reachable is still running, and it owns
		// the port until something kills it.
		stop()
		return nil, nil, err
	}
	return target, stop, nil
}

// appDir locates the web app relative to this process's working directory,
// because the dev server compiles the working tree — an embedded copy is
// exactly what --dev exists to bypass.
func appDir() (string, error) {
	working, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := working; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "app")
		if _, err := os.Stat(filepath.Join(candidate, "package.json")); err == nil {
			return candidate, nil
		}
		if parent := filepath.Dir(dir); parent == dir {
			return "", fmt.Errorf(
				"--dev serves the working tree, but no app/package.json was found at or above %s", working)
		}
	}
}

// freePort asks the kernel for an unused port and hands it back. There is a race
// between closing this listener and Vite binding it, which is why Vite is told
// --strictPort: losing the race must fail loudly rather than silently serve
// somewhere the proxy is not pointed.
func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("find a free port for vite: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, fmt.Errorf("release vite port %d: %w", port, err)
	}
	return port, nil
}

func waitForVite(ctx context.Context, target *url.URL) error {
	deadline := time.Now().Add(viteStartup)
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return err
		}
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			_ = response.Body.Close()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("vite did not answer on %s within %s: %w", target, viteStartup, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

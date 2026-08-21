package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

type Options struct {
	RepositoryRoot string
	SourceDir      string
	BridgePath     string
	Check          bool
}

func Generate(ctx context.Context, options Options) error {
	resolved, err := resolveOptions(options)
	if err != nil {
		return err
	}
	if err := validatePinnedSource(ctx, resolved.SourceDir); err != nil {
		return err
	}
	argumentData, err := exportArguments(ctx, resolved)
	if err != nil {
		return err
	}
	argumentCatalog, err := arguments.LoadJSON(argumentData)
	if err != nil {
		return err
	}
	catalogData, _, err := catalog.Generate(resolved.SourceDir)
	if err != nil {
		return err
	}
	checkCatalog, err := catalog.Unmarshal(catalogData)
	if err != nil {
		return err
	}
	artifacts, err := buildArtifacts(argumentCatalog, checkCatalog, catalogData)
	if err != nil {
		return err
	}
	if err := validatePortableArtifacts(resolved.RepositoryRoot, artifacts); err != nil {
		return err
	}
	if resolved.Check {
		return checkArtifacts(os.DirFS(resolved.RepositoryRoot), artifacts)
	}
	if err := writeArtifacts(resolved.RepositoryRoot, artifacts); err != nil {
		return err
	}
	return checkArtifacts(os.DirFS(resolved.RepositoryRoot), artifacts)
}

func resolveOptions(options Options) (Options, error) {
	if options.RepositoryRoot == "" {
		options.RepositoryRoot = "."
	}
	root, err := filepath.Abs(options.RepositoryRoot)
	if err != nil {
		return Options{}, fmt.Errorf("resolve repository root: %w", err)
	}
	options.RepositoryRoot = root
	if options.SourceDir == "" {
		options.SourceDir = filepath.Join(root, "third_party", "prowler")
	} else if !filepath.IsAbs(options.SourceDir) {
		options.SourceDir = filepath.Join(root, options.SourceDir)
	}
	if options.BridgePath == "" {
		options.BridgePath = filepath.Join(root, "hack", "gen-prowler", "export.py")
	} else if !filepath.IsAbs(options.BridgePath) {
		options.BridgePath = filepath.Join(root, options.BridgePath)
	}
	return options, nil
}

func validatePinnedSource(ctx context.Context, source string) error {
	head, err := gitOutput(ctx, source, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if head != schema.PinnedCommit {
		return fmt.Errorf("prowler source commit drift: expected %s, got %s", schema.PinnedCommit, head)
	}
	status, err := gitOutput(ctx, source, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("prowler source has local changes; generation requires the exact pinned tree:\n%s", status)
	}
	return nil
}

func gitOutput(ctx context.Context, source string, arguments ...string) (string, error) {
	commandArguments := append([]string{"-C", source}, arguments...)
	command := exec.CommandContext(ctx, "git", commandArguments...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("inspect Prowler source with git: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(output)), nil
}

func exportArguments(ctx context.Context, options Options) ([]byte, error) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		return nil, fmt.Errorf("generate Prowler schemas: uv is required: %w", err)
	}
	venv := filepath.Join(options.RepositoryRoot, ".tmp", "prowler-generator-venv")
	cache := filepath.Join(options.RepositoryRoot, ".tmp", "uv-cache")
	if err := os.MkdirAll(filepath.Dir(venv), 0o755); err != nil {
		return nil, fmt.Errorf("create Prowler generator scratch directory: %w", err)
	}
	command := exec.CommandContext(
		ctx, uv, "run", "--project", options.SourceDir, "--locked", "python",
		options.BridgePath, "--source", options.SourceDir,
	)
	command.Dir = options.SourceDir
	command.Env = append(os.Environ(), "UV_PROJECT_ENVIRONMENT="+venv, "UV_CACHE_DIR="+cache)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("export Prowler argparse metadata: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}

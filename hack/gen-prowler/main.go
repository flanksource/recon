package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func main() {
	repository := flag.String("repo", ".", "recon repository root")
	source := flag.String("source", "third_party/prowler", "pinned Prowler source directory")
	bridge := flag.String("bridge", "hack/gen-prowler/export.py", "argparse export bridge")
	check := flag.Bool("check", false, "fail when checked-in artifacts have drifted")
	flag.Parse()

	if err := Generate(context.Background(), Options{
		RepositoryRoot: *repository,
		SourceDir:      *source,
		BridgePath:     *bridge,
		Check:          *check,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		fmt.Println("Prowler generated artifacts are current")
	} else {
		fmt.Println("generated Prowler catalog and provider schemas")
	}
}

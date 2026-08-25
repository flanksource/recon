// Command gen-configdb-identity derives the config-db vocabularies recon needs
// to look a resource up in Mission Control's catalog.
//
// The mapping lives in config-db, which recon deliberately does not depend on:
// it would pull the whole cloud-SDK tree in for a handful of string tables. So
// the tables are generated from config-db's own source at a pinned checkout and
// committed, exactly as the Prowler catalogue is, with --check to fail the build
// when the checked-in copy has drifted from upstream.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	repository := flag.String("repo", ".", "recon repository root")
	source := flag.String("source", "third_party/config-db", "pinned config-db source directory")
	check := flag.Bool("check", false, "fail when the checked-in table has drifted")
	flag.Parse()

	if err := Generate(Options{RepositoryRoot: *repository, SourceDir: *source, Check: *check}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		fmt.Println("config-db identity table is current")
	} else {
		fmt.Println("generated the config-db identity table")
	}
}

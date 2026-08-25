// Command ocsf-census reports what a prowler OCSF report contains.
//
// The design's numbers — 190 records naming 94 resources, of which 141 are
// passes — came from counting a real report by hand. This is that count, kept
// so the claims can be rechecked against a new report rather than trusted.
//
//	go run ./hack/ocsf-census <report.ocsf.json>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type record struct {
	StatusCode string `json:"status_code"`
	Cloud      struct {
		Account struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
	Resources []struct {
		UID  string `json:"uid"`
		Type string `json:"type"`
	} `json:"resources"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: ocsf-census <report.ocsf.json>")
		os.Exit(2)
	}

	body, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var records []record
	if err := json.Unmarshal(body, &records); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	statuses := map[string]int{}
	// Three keyings, because the difference between them is the whole argument
	// for the natural key: uid alone merges `default` across projects, and
	// adding type splits one project into a row per service.
	byUID := map[string]struct{}{}
	byAccountUID := map[string]struct{}{}
	byAccountTypeUID := map[string]struct{}{}
	unstable := map[string]map[string]struct{}{}

	for _, r := range records {
		statuses[r.StatusCode]++
		account := r.Cloud.Account.UID
		for _, resource := range r.Resources {
			byUID[resource.UID] = struct{}{}
			byAccountUID[account+"/"+resource.UID] = struct{}{}
			byAccountTypeUID[account+"/"+resource.Type+"/"+resource.UID] = struct{}{}

			key := account + "/" + resource.UID
			if unstable[key] == nil {
				unstable[key] = map[string]struct{}{}
			}
			unstable[key][resource.Type] = struct{}{}
		}
	}

	var flapping []string
	for key, types := range unstable {
		if len(types) > 1 {
			flapping = append(flapping, fmt.Sprintf("%s (%d types)", key, len(types)))
		}
	}
	sort.Strings(flapping)

	fmt.Printf("records                       %d\n", len(records))
	for _, status := range []string{"FAIL", "PASS", "MANUAL"} {
		fmt.Printf("  %-28s%d\n", status, statuses[status])
	}
	fmt.Printf("distinct uid                  %d\n", len(byUID))
	fmt.Printf("distinct (account, uid)       %d   <- the natural key\n", len(byAccountUID))
	fmt.Printf("distinct (account, type, uid) %d\n", len(byAccountTypeUID))
	fmt.Printf("uids whose type is unstable   %d\n", len(flapping))
	for _, key := range flapping {
		fmt.Printf("  %s\n", key)
	}
}

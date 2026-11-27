package e2e

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	ginkgotypes "github.com/onsi/ginkgo/v2/types"
)

func PrintPerformanceSummary(report ginkgotypes.Report) {
	type entry struct {
		name  string
		value string
	}
	type section struct {
		title   string
		state   string
		entries []entry
	}

	var sections []section
	for _, spec := range report.SpecReports {
		if len(spec.ReportEntries) == 0 && !spec.Failed() {
			continue
		}

		title := strings.Join(spec.ContainerHierarchyTexts, " > ")
		if spec.LeafNodeText != "" {
			title += " > " + spec.LeafNodeText
		}

		state := "PASS"
		if spec.Failed() {
			state = "FAIL"
		}
		if spec.State == ginkgotypes.SpecStateSkipped {
			state = "SKIP"
		}

		s := section{title: title, state: state}
		for _, re := range spec.ReportEntries {
			s.entries = append(s.entries, entry{
				name:  re.Name,
				value: re.StringRepresentation(),
			})
		}
		sections = append(sections, s)
	}

	if len(sections) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, strings.Repeat("=", 72))
	fmt.Fprintln(os.Stdout, "  PERFORMANCE TEST RESULTS")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", 72))

	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
	for _, s := range sections {
		fmt.Fprintln(w)
		stateTag := fmt.Sprintf("[%s]", s.state)
		fmt.Fprintf(w, "  %s\t%s\n", s.title, stateTag)
		fmt.Fprintf(w, "  %s\t\n", strings.Repeat("-", len(s.title)))
		for _, e := range s.entries {
			fmt.Fprintf(w, "    %s\t%s\n", e.name, e.value)
		}
	}
	w.Flush()

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, strings.Repeat("=", 72))

	passed := 0
	failed := 0
	skipped := 0
	for _, s := range sections {
		switch s.state {
		case "PASS":
			passed++
		case "FAIL":
			failed++
		case "SKIP":
			skipped++
		}
	}
	fmt.Fprintf(os.Stdout, "  Total: %d passed, %d failed, %d skipped\n",
		passed, failed, skipped)
	fmt.Fprintln(os.Stdout, strings.Repeat("=", 72))
}

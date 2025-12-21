// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/google/go-github/v80/github"
	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vex/internal/pkg/scanner"
	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/pkg/gitversion"
)

func loadGrypeDB() (vulnerability.Provider, error) {
	db, status, err := grype.LoadVulnerabilityDB(
		distribution.DefaultConfig(),
		installation.DefaultConfig(clio.Identification{
			Name: "talos-vex",
		}),
		true,
	)
	if status == nil || status.Error != nil {
		return nil, err
	}

	return db, nil
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan releases matching the rules",
	Long: `Scan releases matching the rules, using the provided VEX YAML source
	Usage: release-scan scan`,
	Args: cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		err := os.MkdirAll(options.OutputDir, 0o755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output directory %s: %s\n", options.OutputDir, err)

			return
		}

		client := github.NewClient(nil)

		// Use token if provided, for higher limits
		if token, exists := os.LookupEnv("GITHUB_TOKEN"); exists {
			client = client.WithAuthToken(token)
		}

		data, err := v1alpha1.LoadExploitabilityData(options.DataFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading exploitability data file %s: %s\n", options.DataFile, err)

			return
		}

		if err = data.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "error validating exploitability data: %s\n", err)

			return
		}

		sc := scanner.Scanner{
			GithubClient: client,
			Owner:        options.Owner,
			Repo:         options.Repo,
			OutputDir:    options.OutputDir,

			VexData:   data,
			SbomRegex: regexp.MustCompile(options.MatchFiles),
		}

		if sc.DB, err = loadGrypeDB(); err != nil {
			fmt.Fprintf(os.Stderr, "error loading vulnerability db: %s\n", err)

			return
		}
		defer sc.DB.Close()

		skipRegex := regexp.MustCompile(options.SkipTags)
		page := 0
		for {
			releases, result, err := client.Repositories.ListReleases(context.TODO(), options.Owner, options.Repo, &github.ListOptions{PerPage: 100, Page: page})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error fetching releases: %s\n", err)

				return
			}

			done := false

			for _, release := range releases {
				ver := release.GetTagName()

				cmp := gitversion.CompareVersions(ver, options.Version)
				if cmp < 0 || skipRegex.MatchString(ver) {
					continue
				}

				if err := sc.ScanRelease(*release); err != nil {
					fmt.Fprintf(os.Stderr, "Scan failed: %s\n", err)

					break
				}

				// GitHub returns releases ordered from newest to oldest, therefore we're done when reached the oldest scanned version
				if cmp == 0 {
					done = true

					break
				}
			}

			if done {
				break
			}

			page = result.NextPage
		}
	},
}

func init() {
	scanCmd.Flags().StringVarP(&options.DataFile, "source-file", "", "", "Path to the YAML file containing data for VEX generation")
	scanCmd.Flags().StringVarP(&options.Version, "from", "", "v1.11.0", "Minimum version that should be scanned")
	scanCmd.Flags().StringVarP(&options.Owner, "owner", "o", "siderolabs", "GitHub repo owner")
	scanCmd.Flags().StringVarP(&options.Repo, "repo", "r", "talos", "GitHub repo to get releases from")
	scanCmd.Flags().StringVarP(&options.OutputDir, "output-dir", "O", "_out", "Directory to save results to")
	// At least currently SBOMs are not arch-dependent
	scanCmd.Flags().StringVarP(&options.MatchFiles, "match", "m", ".*\\-arm64.spdx\\.json$", "Regex for SBOM files to scan in each release")
	scanCmd.Flags().StringVarP(&options.SkipTags, "skip", "", "(alpha|beta|rc)", "Regex of versions to skip (e.g. unsupported prereleases)")
	rootCmd.AddCommand(scanCmd)
}

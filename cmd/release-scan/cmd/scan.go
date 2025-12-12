// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/pkg"
	jsonPresenter "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vex"
	"github.com/google/go-github/v80/github"
	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/pkg/vexgen"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan releases matching the rules",
	Long: `Scan releases matching the rules, using the provided VEX YAML source
	Usage: release-scan scan --source-file <path> --from <version>
	Source file should be a YAML file containing exploitability data.
	Start version is the minimum version of the product to scan.`,
	Args: cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		err := os.MkdirAll(options.OutputDir, 0o755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output directory %s: %s", options.OutputDir, err)

			return
		}

		client := github.NewClient(nil)

		// Use token if provided, for higher limits
		if token, exists := os.LookupEnv("GITHUB_TOKEN"); exists {
			client = client.WithAuthToken(token)
		}

		data, err := v1alpha1.LoadExploitabilityData(options.DataFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading exploitability data file %s: %s", options.DataFile, err)

			return
		}

		if err = data.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "error validating exploitability data: %s", err)

			return
		}

		db, status, err := grype.LoadVulnerabilityDB(
			distribution.DefaultConfig(),
			installation.DefaultConfig(clio.Identification{
				Name: "talos-vex",
			}),
			true,
		)
		if status == nil || status.Error != nil {
			fmt.Fprintf(os.Stderr, "error loading vulnerability db: %s", err)

			return
		}
		defer db.Close()

		ver := options.Version
		sbomFilename := "/tmp/talos-arm64.spdx.json"
		// sbomName := path.Base(sbomFilename)
		{
			curDir := path.Join(options.OutputDir, ver)
			vexPath := path.Join(curDir, "vex.json")
			err := os.MkdirAll(curDir, 0o755)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating version workdir: %s", err)

				return
			}

			doc, err := vexgen.Populate(data, ver, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error populating VEX document: %s", err)

				return
			}

			f, err := os.OpenFile(vexPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating VEX file: %s", err)

				return
			}

			err = vexgen.Serialize(doc, f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error serializing VEX document: %s", err)

				return
			}

			f.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error closing VEX file: %s", err)

				return
			}

			vexProcessor, err := vex.NewProcessor(vex.ProcessorOptions{
				Documents: []string{vexPath},
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error initializing Grype VEX processor: %s", err)
				return
			}

			vulnMatcher := grype.VulnerabilityMatcher{
				VulnerabilityProvider: db,
				VexProcessor:          vexProcessor,
			}
			packages, pkgContext, s, err := pkg.Provide(fmt.Sprintf("sbom:%s", sbomFilename), pkg.ProviderConfig{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading SBOM: %s", err)

				return
			}

			matches, _, err := vulnMatcher.FindMatches(packages, pkgContext)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error scanning SBOM: %s", err)

				return
			}

			modelDocument, err := models.NewDocument(
				clio.Identification{
					Name: "talos-vex",
				},
				packages,
				pkgContext,
				*matches,
				nil, // Do not report vulnerabilities suppressed by VEX (fixed/not_affected)
				db,
				nil,
				nil,
				models.SortByPackage,
				true,
			)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error generating report: %s", err)

				return
			}

			f, err = os.OpenFile(path.Join(curDir, "report.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating report file: %s", err)

				return
			}

			presenter := jsonPresenter.NewPresenter(models.PresenterConfig{
				Document: modelDocument,
				Pretty:   true,
				SBOM:     s,
			})

			if err = presenter.Present(f); err != nil {
				fmt.Fprintf(os.Stderr, "error presenting report file: %s", err)

				return
			}
		}

		// page := 0
		// for {
		// 	releases, result, err := client.Repositories.ListReleases(context.TODO(), options.Owner, options.Repo, &github.ListOptions{PerPage: 100, Page: page})
		// 	if err != nil {
		// 		fmt.Fprintf(os.Stderr, "error fetching releases: %s", err)

		// 		return
		// 	}
		// 	fmt.Println("Rate", result.Rate)
		// 	done := false

		// 	for _, release := range releases {
		// 		ver := release.GetTagName()

		// 		cmp := gitversion.CompareVersions(ver, options.Version)
		// 		if cmp >= 0 {
		// 			fmt.Println("match", ver)
		// 			// GitHub returns releases ordered from newest to oldest, therefore we're done when reached the oldest scanned version
		// 			if cmp == 0 {
		// 				done = true
		// 				break
		// 			}
		// 		}
		// 	}

		// 	if done {
		// 		break
		// 	}

		// 	page = result.NextPage
		// }

	},
}

func init() {
	scanCmd.Flags().StringVarP(&options.DataFile, "source-file", "", "", "Path to the YAML file containing data for VEX generation")
	scanCmd.Flags().StringVarP(&options.Version, "from", "", "", "Minimum version that should be scanned")
	scanCmd.Flags().StringVarP(&options.Owner, "owner", "o", "siderolabs", "GitHub repo owner")
	scanCmd.Flags().StringVarP(&options.Repo, "repo", "r", "talos", "GitHub repo to get releases from")
	scanCmd.Flags().StringVarP(&options.OutputDir, "output-dir", "O", "_out", "Directory to save results to")
	scanCmd.MarkFlagRequired("from") //nolint:errcheck
	rootCmd.AddCommand(scanCmd)
}

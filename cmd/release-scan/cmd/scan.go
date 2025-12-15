// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/pkg"
	cdxPresenter "github.com/anchore/grype/grype/presenter/cyclonedx"
	jsonPresenter "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	sarifPresenter "github.com/anchore/grype/grype/presenter/sarif"
	tablePresenter "github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
	"github.com/google/go-github/v80/github"
	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/pkg/vexgen"
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

func createVexFile(filepath string, data *v1alpha1.ExploitabilityData, ver string) error {
	doc, err := vexgen.Populate(data, ver, nil)
	if err != nil {
		return fmt.Errorf("error populating VEX document: %w", err)
	}

	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating VEX file: %w", err)
	}
	defer f.Close()

	if err = vexgen.Serialize(doc, f); err != nil {
		return fmt.Errorf("error serializing VEX document: %w", err)
	}

	return nil
}

func scanSBOM(sbomFilename string, vulnMatcher grype.VulnerabilityMatcher, db vulnerability.Provider) (*models.Document, *sbom.SBOM, error) {
	packages, pkgContext, s, err := pkg.Provide(fmt.Sprintf("sbom:%s", sbomFilename), pkg.ProviderConfig{})
	if err != nil {
		return nil, nil, fmt.Errorf("error reading SBOM: %w", err)
	}

	matches, _, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return nil, nil, fmt.Errorf("error scanning SBOM: %w", err)
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
		return nil, nil, fmt.Errorf("error generating report: %w", err)
	}

	return &modelDocument, s, nil
}

func reportJSON(modelDocument models.Document, filename string) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	presenter := jsonPresenter.NewPresenter(models.PresenterConfig{
		Document: modelDocument,
		Pretty:   true,
	})

	if err = presenter.Present(f); err != nil {
		return fmt.Errorf("error presenting report file: %w", err)
	}

	return nil
}

func reportCyclonedxJSON(modelDocument models.Document, filename string, s *sbom.SBOM) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	presenter := cdxPresenter.NewJSONPresenter(models.PresenterConfig{
		Document: modelDocument,
		Pretty:   true,
		SBOM:     s,
	})

	if err = presenter.Present(f); err != nil {
		return fmt.Errorf("error presenting report file: %w", err)
	}

	return nil
}

func reportSARIF(modelDocument models.Document, filename string, s *sbom.SBOM) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	presenter := sarifPresenter.NewPresenter(models.PresenterConfig{
		Document: modelDocument,
		Pretty:   true,
		SBOM:     s,
	})

	if err = presenter.Present(f); err != nil {
		return fmt.Errorf("error presenting report file: %w", err)
	}

	return nil
}

func reportTable(modelDocument models.Document, filename string) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	presenter := tablePresenter.NewPresenter(models.PresenterConfig{
		Document: modelDocument,
		Pretty:   true,
		// SBOM:     s,
	}, false)

	if err = presenter.Present(f); err != nil {
		return fmt.Errorf("error presenting report file: %w", err)
	}

	return nil
}

func downloadAsset(client *github.Client, asset github.ReleaseAsset, dir string) (string, error) {
	rc, _, err := client.Repositories.DownloadReleaseAsset(
		context.TODO(),
		options.Owner,
		options.Repo,
		*asset.ID,
		http.DefaultClient,
	)
	if err != nil {
		return "", err
	}

	filename := path.Join(dir, *asset.Name)

	f, err := os.OpenFile(
		filename,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644,
	)
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = io.Copy(f, rc)

	return filename, err
}

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

		var db vulnerability.Provider
		if db, err = loadGrypeDB(); err != nil {
			fmt.Fprintf(os.Stderr, "error loading vulnerability db: %s", err)

			return
		}
		defer db.Close()

		rl, res, err := client.RateLimit.Get(context.TODO())
		fmt.Println("INFO: GitHub API rate info", rl, res, err)
		sbomRegex := regexp.MustCompile(options.MatchFiles)
		skipRegex := regexp.MustCompile(options.SkipTags)
		page := 0
		for {
			releases, result, err := client.Repositories.ListReleases(context.TODO(), options.Owner, options.Repo, &github.ListOptions{PerPage: 100, Page: page})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error fetching releases: %s", err)

				return
			}

			done := false

			for _, release := range releases {
				ver := release.GetTagName()
				verDir := path.Join(options.OutputDir, ver)

				cmp := gitversion.CompareVersions(ver, options.Version)
				if cmp < 0 || skipRegex.MatchString(ver) {
					continue
				}

				err := os.MkdirAll(verDir, 0o755)
				if err != nil {
					fmt.Fprintln(os.Stderr, "error creating version workdir: %w", err)
				}

				fmt.Println("ver:", ver)
				vexPath := path.Join(verDir, "vex.json")

				err = createVexFile(vexPath, data, ver)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error creating VEX: %s", err)

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

				for _, asset := range release.Assets {
					if !sbomRegex.MatchString(*asset.Name) {
						continue
					}

					var sbomFilename string
					fmt.Println("- downloading", *asset.Name)
					if sbomFilename, err = downloadAsset(client, *asset, verDir); err != nil {
						fmt.Fprintf(os.Stderr, "error downloading %s: %s", *asset.Name, err)
					}

					modelDocument, s, err := scanSBOM(sbomFilename, vulnMatcher, db)
					if err != nil {
						fmt.Fprintf(os.Stderr, "error scanning: %s", err)

						return
					}

					if err = reportJSON(*modelDocument, path.Join(verDir, *asset.Name+"-report.json")); err != nil {
						fmt.Fprintf(os.Stderr, "error reporting: %s", err)

						return
					}

					if err = reportCyclonedxJSON(*modelDocument, path.Join(verDir, *asset.Name+"-report.cdx.json"), s); err != nil {
						fmt.Fprintf(os.Stderr, "error reporting: %s", err)

						return
					}

					if err = reportSARIF(*modelDocument, path.Join(verDir, *asset.Name+"-report.sarif.json"), s); err != nil {
						fmt.Fprintf(os.Stderr, "error reporting: %s", err)

						return
					}

					if err = reportTable(*modelDocument, path.Join(verDir, *asset.Name+"-report.table.txt")); err != nil {
						fmt.Fprintf(os.Stderr, "error reporting: %s", err)

						return
					}
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

		rl, res, err = client.RateLimit.Get(context.TODO())
		fmt.Println("INFO: GitHub API rate info", rl, res, err)
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

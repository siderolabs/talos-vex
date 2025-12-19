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
	"github.com/wagoodman/go-presenter"

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

func formatReport(modelDocument models.Document, filename string, s *sbom.SBOM, format string) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	config := models.PresenterConfig{
		Document: modelDocument,
		Pretty:   true,
		SBOM:     s,
	}

	var presenter presenter.Presenter

	switch format {
	case "json":
		presenter = jsonPresenter.NewPresenter(config)
	case "table":
		presenter = tablePresenter.NewPresenter(config, false)
	case "sarif":
		presenter = sarifPresenter.NewPresenter(config)
	case "cdx":
		presenter = cdxPresenter.NewJSONPresenter(config)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}

	if err = presenter.Present(f); err != nil {
		return fmt.Errorf("error presenting report file: %w", err)
	}

	return nil
}

type scanner struct {
	client    *github.Client
	db        vulnerability.Provider
	vexData   *v1alpha1.ExploitabilityData
	sbomRegex *regexp.Regexp
}

func (sc *scanner) createVexFile(filepath string, ver string) error {
	doc, err := vexgen.Populate(sc.vexData, ver, nil)
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

func (sc *scanner) scanSBOM(sbomPath string, vulnMatcher grype.VulnerabilityMatcher) (*models.Document, *sbom.SBOM, error) {
	packages, pkgContext, s, err := pkg.Provide(fmt.Sprintf("sbom:%s", sbomPath), pkg.ProviderConfig{})
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
		sc.db,
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

func (sc *scanner) downloadAsset(asset github.ReleaseAsset, dir string) (string, error) {
	rc, _, err := sc.client.Repositories.DownloadReleaseAsset(
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

func (sc *scanner) scanRelease(release github.RepositoryRelease) error {
	version := *release.Name
	dir := path.Join(options.OutputDir, version)

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return fmt.Errorf("error creating version workdir: %w", err)
	}

	fmt.Println("Scanning version:", version)

	vexPath := path.Join(dir, "vex.json")

	err = sc.createVexFile(vexPath, version)
	if err != nil {
		return fmt.Errorf("error creating VEX: %w", err)
	}

	vexProcessor, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: []string{vexPath},
	})
	if err != nil {
		return fmt.Errorf("error initializing Grype VEX processor: %w", err)
	}

	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: sc.db,
		VexProcessor:          vexProcessor,
	}

	for _, asset := range release.Assets {
		if !sc.sbomRegex.MatchString(*asset.Name) {
			continue
		}

		var sbomFilename string

		fmt.Println("- downloading", *asset.Name)

		if sbomFilename, err = sc.downloadAsset(*asset, dir); err != nil {
			return fmt.Errorf("error downloading %s: %w", *asset.Name, err)
		}

		modelDocument, s, err := sc.scanSBOM(sbomFilename, vulnMatcher)
		if err != nil {
			return fmt.Errorf("error scanning: %w", err)
		}

		for _, reporter := range []struct {
			format string
			suffix string
		}{
			{
				format: "json",
				suffix: "-report.json",
			}, {
				format: "cdx",
				suffix: "-report.cdx.json",
			}, {
				format: "sarif",
				suffix: "-report.sarif.json",
			}, {
				format: "table",
				suffix: "-report.table.txt",
			},
		} {
			if err = formatReport(
				*modelDocument,
				path.Join(dir, *asset.Name+reporter.suffix),
				s,
				reporter.format,
			); err != nil {
				return fmt.Errorf("error reporting: %w", err)
			}
		}
	}

	return nil
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

		sc := scanner{
			client:    client,
			vexData:   data,
			sbomRegex: regexp.MustCompile(options.MatchFiles),
		}

		if sc.db, err = loadGrypeDB(); err != nil {
			fmt.Fprintf(os.Stderr, "error loading vulnerability db: %s", err)

			return
		}
		defer sc.db.Close()

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

				cmp := gitversion.CompareVersions(ver, options.Version)
				if cmp < 0 || skipRegex.MatchString(ver) {
					continue
				}

				if err := sc.scanRelease(*release); err != nil {
					fmt.Println("Scan failed:", err)

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

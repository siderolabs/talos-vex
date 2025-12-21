// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package scanner

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
	"github.com/wagoodman/go-presenter"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/pkg/vexgen"
)

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

type Scanner struct {
	GithubClient *github.Client
	Owner        string
	Repo         string
	OutputDir    string

	DB        vulnerability.Provider
	VexData   *v1alpha1.ExploitabilityData
	SbomRegex *regexp.Regexp
}

func (sc *Scanner) createVexFile(filepath string, ver string) error {
	doc, err := vexgen.Populate(sc.VexData, ver, nil)
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

func (sc *Scanner) scanSBOM(sbomPath string, vulnMatcher grype.VulnerabilityMatcher) (*models.Document, *sbom.SBOM, error) {
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
		sc.DB,
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

func (sc *Scanner) downloadAsset(asset github.ReleaseAsset, dir string) (string, error) {
	rc, _, err := sc.GithubClient.Repositories.DownloadReleaseAsset(
		context.TODO(),
		sc.Owner,
		sc.Repo,
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

// ScanRelease scans matching SBOMs found in the passed GitHub release.
func (sc *Scanner) ScanRelease(release github.RepositoryRelease) error {
	version := *release.Name
	dir := path.Join(sc.OutputDir, version)

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
		VulnerabilityProvider: sc.DB,
		VexProcessor:          vexProcessor,
	}

	for _, asset := range release.Assets {
		if !sc.SbomRegex.MatchString(*asset.Name) {
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

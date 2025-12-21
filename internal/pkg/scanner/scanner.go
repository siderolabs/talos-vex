// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package scanner

import (
	"fmt"
	"os"
	"path"
	"time"

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
	"github.com/wagoodman/go-presenter"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/pkg/vexgen"
)

// FormatReport formats a scanning report into the specified format and writes into a file.
func FormatReport(modelDocument models.Document, filename string, s *sbom.SBOM, format string) error {
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

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	if err = presenter.Present(f); err != nil {
		return fmt.Errorf("error presenting report file: %w", err)
	}

	return nil
}

type Scanner struct {
	db        vulnerability.Provider
	vexData   *v1alpha1.ExploitabilityData
	timestamp *time.Time
}

// NewScanner creates a scanner with given exploitability data and loads a DB.
func NewScanner(vexData *v1alpha1.ExploitabilityData, timestamp *time.Time) (*Scanner, error) {
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

	return &Scanner{
		vexData:   vexData,
		db:        db,
		timestamp: timestamp,
	}, nil
}

// Close closes the scanner, unloading the vulnerability database.
func (sc *Scanner) Close() error {
	return sc.db.Close()
}

// CreateVexFile populates a VEX file in a workdir.
func (sc *Scanner) CreateVexFile(workdir, ver string) (string, error) {
	filepath := path.Join(workdir, "vex.json")

	doc, err := vexgen.Populate(sc.vexData, ver, sc.timestamp)
	if err != nil {
		return "", fmt.Errorf("error populating VEX document: %w", err)
	}

	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("error creating VEX file: %w", err)
	}

	if err = vexgen.Serialize(doc, f); err != nil {
		return "", fmt.Errorf("error serializing VEX document: %w", err)
	}

	if err = f.Close(); err != nil {
		return "", fmt.Errorf("error closing VEX document: %w", err)
	}

	return filepath, nil
}

// ScanSBOM scans an SBOM file from path, using a VEX file to determine significance.
func (sc *Scanner) ScanSBOM(sbomPath, vexPath string) (*models.Document, *sbom.SBOM, error) {
	vexProcessor, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: []string{vexPath},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error initializing Grype VEX processor: %w", err)
	}

	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: sc.db,
		VexProcessor:          vexProcessor,
	}

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

	if sc.timestamp != nil {
		modelDocument.Descriptor.Timestamp = sc.timestamp.Format("2025-12-18T17:09:08.143727492+01:00")
	}

	return &modelDocument, s, nil
}

// ScanRelease scans matching SBOMs found in the passed GitHub release.
func (sc *Scanner) ScanRelease(version, workdir string, sbomFiles []string) error {
	vexPath, err := sc.CreateVexFile(workdir, version)
	if err != nil {
		return fmt.Errorf("error creating VEX: %w", err)
	}

	for _, sbomFile := range sbomFiles {
		modelDocument, s, err := sc.ScanSBOM(path.Join(workdir, sbomFile), vexPath)
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
			if err = FormatReport(
				*modelDocument,
				path.Join(workdir, sbomFile+reporter.suffix),
				s,
				reporter.format,
			); err != nil {
				return fmt.Errorf("error reporting: %w", err)
			}
		}
	}

	return nil
}

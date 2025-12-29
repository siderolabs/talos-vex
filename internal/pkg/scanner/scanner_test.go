// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package scanner_test

import (
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/sbom"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"

	"github.com/siderolabs/talos-vex/internal/pkg/scanner"
	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
)

var (
	testData = v1alpha1.ExploitabilityData{
		Author: "Test Author",
		IDs: map[vex.IdentifierType]string{
			vex.PURL: "pkg:generic/talos",
		},
		Statements: []v1alpha1.Statement{
			{
				Name:        "CVE-2025-26519",
				Description: "Musl versions before 1.2.6 are vulnerable to invalid input",
				Created:     "2025-07-14T12:00:00Z",
				From:        "v1.10.0-alpha.1-35-g46d67fe44",
				Status:      vex.StatusFixed,
				StatusNotes: "https://github.com/siderolabs/toolchain/commit/818b320288afa40da07f95998b8739bf211a9f9c",
			},
		},
	}
	testDocument = models.Document{
		Matches: []models.Match{
			{
				Vulnerability: models.Vulnerability{
					VulnerabilityMetadata: models.VulnerabilityMetadata{
						ID: "CVE-1234-5678",
					},
				},
			},
		},
	}
)

func assertFileEqual(t *testing.T, expectedFile, actualFile string) {
	expected, err := os.ReadFile(expectedFile)
	assert.NoError(t, err)

	actual, err := os.ReadFile(actualFile)
	assert.NoError(t, err)

	assert.Equal(t, string(expected), string(actual))
}

func TestFormatReport(t *testing.T) {
	dir := t.TempDir()

	reportFile := filepath.Join(dir, "report.json")
	err := scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, "json")
	assert.NoError(t, err)

	assertFileEqual(t, "./testdata/report.json", reportFile)

	reportFile = filepath.Join(dir, "report.table")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, "table")
	assert.NoError(t, err)

	assertFileEqual(t, "./testdata/report.table", reportFile)

	reportFile = filepath.Join(dir, "report.sarif")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, "sarif")
	assert.NoError(t, err)

	assertFileEqual(t, "./testdata/report.sarif", reportFile)

	reportFile = filepath.Join(dir, "report.cdx")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, "cdx")
	assert.NoError(t, err)

	actual, err := os.ReadFile(reportFile)
	assert.NoError(t, err)

	expected, err := os.ReadFile("./testdata/report.cdx")
	assert.NoError(t, err)

	// Only test the deterministic part
	assert.Contains(t, string(actual), string(expected))

	reportFile = filepath.Join(dir, "report.unk")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, "unk")
	assert.ErrorContains(t, err, "unknown format: unk")

	_, err = os.ReadFile(reportFile)
	assert.ErrorContains(t, err, "no such file or directory")
}

func TestNewScanner(t *testing.T) {
	sc, err := scanner.NewScanner(&testData, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sc)

	assert.NoError(t, sc.Close())
}

func TestCreateVexFile(t *testing.T) {
	timestamp, err := time.Parse(time.RFC3339, "2025-07-16T13:46:22Z")
	assert.NoError(t, err)

	sc, err := scanner.NewScanner(&testData, &timestamp)
	assert.NoError(t, err)
	assert.NotNil(t, sc)

	workdir := t.TempDir()
	vexPath, err := sc.CreateVexFile(workdir, "v1.11.0")
	assert.NoError(t, err)
	assert.Contains(t, vexPath, "/vex.json")

	assertFileEqual(t, "./testdata/26519.json", vexPath)
}

func TestScanSBOM(t *testing.T) {
	timestamp, err := time.Parse(time.RFC3339, "2025-07-16T13:46:22Z")
	assert.NoError(t, err)

	sc, err := scanner.NewScanner(&testData, &timestamp)
	assert.NoError(t, err)
	assert.NotNil(t, sc)

	doc, sbom, err := sc.ScanSBOM("./testdata/test.spdx.json", "./testdata/26519.json")
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.NotNil(t, sbom)
	assert.Equal(t, 2, sbom.Artifacts.Packages.PackageCount()) // two packages left for test

	matchesWithVex := len(doc.Matches)
	found26519 := false
	found67499 := false

	for _, m := range doc.Matches {
		switch m.Vulnerability.ID {
		case "CVE-2025-26519":
			found26519 = true
		case "CVE-2025-67499":
			found67499 = true
		}
	}

	assert.False(t, found26519, "expected not to find CVE-2025-26519")
	assert.True(t, found67499, "expected to find CVE-2025-67499")

	doc, sbom, err = sc.ScanSBOM("./testdata/test.spdx.json", "./testdata/empty-vex.json")
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.NotNil(t, sbom)
	assert.Equal(t, 2, sbom.Artifacts.Packages.PackageCount()) // two packages left for test

	matchesWithoutVex := len(doc.Matches)
	found26519 = false
	found67499 = false

	for _, m := range doc.Matches {
		switch m.Vulnerability.ID {
		case "CVE-2025-26519":
			found26519 = true
		case "CVE-2025-67499":
			found67499 = true
		}
	}

	assert.True(t, found26519, "expected to find CVE-2025-26519")
	assert.True(t, found67499, "expected to find CVE-2025-67499")

	assert.Equal(t, 1, matchesWithoutVex-matchesWithVex)
}

func TestScanRelease(t *testing.T) {
	timestamp, err := time.Parse(time.RFC3339, "2025-07-16T13:46:22Z")
	assert.NoError(t, err)

	sc, err := scanner.NewScanner(&testData, &timestamp)
	assert.NoError(t, err)
	assert.NotNil(t, sc)

	dir := "/tmp/aaa" // t.TempDir()

	os.CopyFS(dir, os.DirFS("./testdata/release"))

	err = sc.ScanRelease("v1.11.0", dir, []string{"test.spdx.json"})
	assert.NoError(t, err)

	for _, f := range []string{
		"test.spdx.json-report.json",
		"test.spdx.json-report.sarif.json",
		"test.spdx.json-report.table.txt",
		"test.spdx.json",
		"vex.json",
	} {
		assertFileEqual(t, path.Join("./testdata/release-result/", f), path.Join(dir, f))
	}
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	_ "embed"
	"fmt"
	"io"
	"os"

	"github.com/openvex/go-vex/pkg/vex"
	"gopkg.in/yaml.v3"
)

type Statement struct {
	Created       string                `yaml:"created"`                 // RFC3339 date on which the statement was created
	Name          vex.VulnerabilityID   `yaml:"name"`                    // Generally should be CVE name
	Description   string                `yaml:"description"`             // Human-readable description of the statement
	From          string                `yaml:"from"`                    // First version this statement applies to
	To            string                `yaml:"to"`                      // Last version this statement applies to
	Status        vex.Status            `yaml:"status"`                  // not_affected, affected, fixed, under_investigation ...
	StatusNotes   string                `yaml:"statusNotes"`             // Human-readable notes about the status
	Justification vex.Justification     `yaml:"justification,omitempty"` // Justification for the not_affected status
	Impact        string                `yaml:"impact,omitempty"`        // Human-readable impact statement of the vulnerability
	Action        string                `yaml:"action,omitempty"`        // "affected" entries MUST include a statement about mitigation actions
	ActionTime    string                `yaml:"actionTime,omitempty"`    // Time when the action statement was created, RFC3339 format
	LastUpdated   string                `yaml:"lastUpdated,omitempty"`   // Time when the statement was last updated, RFC3339 format
	Aliases       []vex.VulnerabilityID `yaml:"aliases"`                 // Alternative names for the vulnerability
}

type ExploitabilityData struct {
	Author     string                        `yaml:"author"`     // Author of the VEX document
	IDs        map[vex.IdentifierType]string `yaml:"ids"`        // IDs (without version) of the product
	Statements []Statement                   `yaml:"statements"` // Statements about vulnerabilities
}

//go:embed data/talos.yaml
var embeddedData []byte

func LoadExploitabilityData(file string) (*ExploitabilityData, error) {
	// By default, use current data for Talos
	contents := embeddedData

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}

		defer f.Close() //nolint:errcheck

		contents, err = io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("error reading file %s: %w", file, err)
		}
	}

	var data ExploitabilityData
	if err := yaml.Unmarshal(contents, &data); err != nil {
		return nil, fmt.Errorf("error unmarshalling data: %w", err)
	}

	return &data, nil
}

// Validate checks validity of common fields in the ExploitabilityData.
func (d *ExploitabilityData) Validate() error {
	if d.Author == "" {
		return fmt.Errorf("author is required")
	}

	if len(d.IDs) == 0 {
		return fmt.Errorf("at least one product ID is required")
	}

	for i, stmt := range d.Statements {
		if stmt.Created == "" {
			return fmt.Errorf("statement %d: created date is required", i)
		}

		if stmt.Name == "" {
			return fmt.Errorf("statement %d: name is required", i)
		}

		if !stmt.Status.Valid() {
			return fmt.Errorf("statement %d: invalid status %q", i, stmt.Status)
		}

		if stmt.Justification != "" && !stmt.Justification.Valid() {
			return fmt.Errorf("statement %d: invalid justification", i)
		}
	}

	return nil
}

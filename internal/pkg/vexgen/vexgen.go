// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package vexgen

import (
	"fmt"
	"io"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/version"
	"github.com/siderolabs/talos-vex/pkg/gitversion"
)

// Populate generates a VEX document from the provided exploitability data
// for the given product version.
func Populate(data *v1alpha1.ExploitabilityData, productVersion string, timestamp *time.Time) (vex.VEX, error) {
	// Timestamp defaults to SOURCE_DATE_EPOCH if set
	doc := vex.New()
	doc.Author = data.Author

	doc.Version = 1

	doc.Tooling = fmt.Sprintf("%s version %s (%s)", version.Name, version.Tag, version.SHA)
	if timestamp != nil {
		doc.Timestamp = timestamp
	}

	productIDs := MakeVersionedProductIDs(data.IDs, productVersion)

	var err error

	doc.Statements, err = ConvertStatements(data.Statements, productIDs, productVersion)
	if err != nil {
		return doc, fmt.Errorf("error converting statement: %w", err)
	}

	return doc, nil
}

// Serialize serializes the VEX document to the provided writer in JSON format, with a reproducible ID.
func Serialize(doc vex.VEX, writer io.Writer) error {
	_, err := doc.GenerateCanonicalID()
	if err != nil {
		return fmt.Errorf("error generating document ID: %w", err)
	}

	if err := doc.ToJSON(writer); err != nil {
		return fmt.Errorf("error converting document to JSON: %w", err)
	}

	return nil
}

// MakeVersionedProductIDs adds the product version to provided identifiers.
func MakeVersionedProductIDs(ids map[vex.IdentifierType]string, productVersion string) map[vex.IdentifierType]string {
	productIDs := make(map[vex.IdentifierType]string)

	for id, idValue := range ids {
		switch id {
		case vex.PURL:
			productIDs[id] = fmt.Sprintf("%s@%s", idValue, productVersion)
		case vex.CPE22, vex.CPE23:
			productIDs[id] = fmt.Sprintf("%s:%s:*:*:*:*:*:*:*", idValue, productVersion)
		}
	}

	return productIDs
}

// ConvertStatements converts the provided statement data to VEX statements,
// filtering out statements that do not apply to the specified product version.
func ConvertStatements(statements []v1alpha1.Statement, productIDs map[vex.IdentifierType]string, productVersion string) ([]vex.Statement, error) {
	result := make([]vex.Statement, 0, len(statements))

	for _, stmt := range statements {
		inRange, err := gitversion.VersionInRange(productVersion, stmt.From, stmt.To)
		if err != nil {
			return result, fmt.Errorf("error checking version range: %w", err)
		} else if !inRange {
			continue
		}

		createdTime, err := time.Parse(time.RFC3339, stmt.Created)
		if err != nil {
			return result, fmt.Errorf("error parsing time: %w", err)
		}

		var actionTime *time.Time
		if stmt.ActionTime != "" {
			actionTimeParsed, err := time.Parse(time.RFC3339, stmt.ActionTime)
			if err != nil {
				return result, fmt.Errorf("error parsing action time: %w", err)
			}

			actionTime = &actionTimeParsed
		}

		var lastUpdated *time.Time
		if stmt.LastUpdated != "" {
			lastUpdatedParsed, err := time.Parse(time.RFC3339, stmt.LastUpdated)
			if err != nil {
				return result, fmt.Errorf("error parsing last updated time: %w", err)
			}

			lastUpdated = &lastUpdatedParsed
		}

		entry := vex.Statement{
			Vulnerability: vex.Vulnerability{
				Name:        stmt.Name,
				Description: stmt.Description,
				Aliases:     stmt.Aliases,
			},
			Products: []vex.Product{
				{
					Component: vex.Component{
						Identifiers: productIDs,
					},
				},
			},
			Status:      stmt.Status,
			StatusNotes: stmt.StatusNotes,
			Timestamp:   &createdTime,
			// for StatusNotAffected we MUST set Justification or ImpactStatement
			Justification:   stmt.Justification,
			ImpactStatement: stmt.Impact,
			// MUST be set for StatusAffected, with optional timestamp
			ActionStatement:          stmt.Action,
			ActionStatementTimestamp: actionTime,
			LastUpdated:              lastUpdated,
		}

		if err := entry.Validate(); err != nil {
			return result, fmt.Errorf("invalid statement: %w", err)
		}

		result = append(result, entry)
	}

	return result, nil
}

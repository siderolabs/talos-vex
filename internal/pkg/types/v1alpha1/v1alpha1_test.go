// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1_test

import (
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
)

func TestEmbeddedData_Validate(t *testing.T) {
	data, err := v1alpha1.LoadExploitabilityData("")
	require.NoError(t, err)

	require.NoError(t, data.Validate())
}

func TestExploitabilityData_Validate(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		data    v1alpha1.ExploitabilityData
		wantErr bool
	}{
		{
			name: "valid data",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Created: "2023-01-01T00:00:00Z",
						Name:    "CVE-2023-1234",
						Status:  vex.StatusNotAffected,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing author",
			data: v1alpha1.ExploitabilityData{
				IDs: map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
			},
			wantErr: true,
			errMsg:  "author is required",
		},
		{
			name: "missing IDs",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{},
			},
			wantErr: true,
			errMsg:  "at least one product ID is required",
		},
		{
			name: "statement missing created date",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Name:   "CVE-2023-1234",
						Status: vex.StatusNotAffected,
					},
				},
			},
			wantErr: true,
			errMsg:  "statement 0: created date is required",
		},
		{
			name: "statement missing name",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Created: "2023-01-01T00:00:00Z",
						Status:  vex.StatusNotAffected,
					},
				},
			},
			wantErr: true,
			errMsg:  "statement 0: name is required",
		},
		{
			name: "statement missing status",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Created: "2023-01-01T00:00:00Z",
						Name:    "CVE-2023-1234",
					},
				},
			},
			wantErr: true,
			errMsg:  "statement 0: invalid status \"\"",
		},
		{
			name: "statement with invalid justification",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Created:       "2023-01-01T00:00:00Z",
						Name:          "CVE-2023-1234",
						Status:        vex.StatusNotAffected,
						Justification: "invalid_justification",
					},
				},
			},
			wantErr: true,
			errMsg:  "statement 0: invalid justification",
		},
		{
			name: "statement with invalid status",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Created: "2023-01-01T00:00:00Z",
						Name:    "CVE-2023-1234",
						Status:  "invalid_status",
					},
				},
			},
			wantErr: true,
			errMsg:  "statement 0: invalid status \"invalid_status\"",
		},
		{
			name: "valid data with justification",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Created:       "2023-01-01T00:00:00Z",
						Name:          "CVE-2023-1234",
						Status:        vex.StatusNotAffected,
						Justification: vex.ComponentNotPresent,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple statements with mixed validity",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{"purl": "pkg:oci/talos@v1.0.0"},
				Statements: []v1alpha1.Statement{
					{
						Created: "2023-01-01T00:00:00Z",
						Name:    "CVE-2023-1234",
						Status:  vex.StatusNotAffected,
					},
					{
						Created: "2023-01-01T00:00:00Z",
						Name:    "CVE-2023-5678",
						Status:  "bad_status",
					},
				},
			},
			wantErr: true,
			errMsg:  "statement 1: invalid status \"bad_status\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.data.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

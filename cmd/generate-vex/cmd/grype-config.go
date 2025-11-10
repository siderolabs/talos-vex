// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v4"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/pkg/vexgen"
)

// Basic config options we need to generate.
type grypeConfigOptions struct {
	Ignore []grypeIgnoreEntry `yaml:"ignore"`
}

type grypeIgnoreEntry struct {
	Vulnerability string `yaml:"vulnerability"`
}

var grypeConfigCmd = &cobra.Command{
	Use:   "grype-config",
	Short: "Generate a Grype configuration for CI",
	Long: `This command is used for Talos CI, silencing vulnerabilities with affected and under_investigation statuses.
	It helps reduce CI noise once a vulnerability has been acknowledged.`,
	Args: cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		data, err := v1alpha1.LoadExploitabilityData(options.DataFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading exploitability data file %s: %s", options.DataFile, err)

			return
		}

		if err = data.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "error validating exploitability data: %s", err)

			return
		}

		statements, err := vexgen.ConvertStatements(data.Statements, make(map[vex.IdentifierType]string), options.Version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error converting statements: %s", err)

			return
		}

		config := grypeConfigOptions{
			Ignore: make([]grypeIgnoreEntry, 0),
		}

		for _, statement := range statements {
			if statement.Status == vex.StatusAffected || statement.Status == vex.StatusUnderInvestigation {
				config.Ignore = append(config.Ignore, grypeIgnoreEntry{
					Vulnerability: string(statement.Vulnerability.Name),
				})
			}
		}

		enc := yaml.NewEncoder(os.Stdout)
		defer enc.Close() //nolint:errcheck
		enc.SetIndent(2)
		if err := enc.Encode(config); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding Grype config to YAML: %s", err)
		}
	},
}

func init() {
	grypeConfigCmd.Flags().StringVarP(&options.DataFile, "source-file", "", "", "Path to the YAML file containing data for VEX generation")
	grypeConfigCmd.Flags().StringVarP(&options.Version, "target-version", "", "", "Version of the VEX document to generate")
	grypeConfigCmd.MarkFlagRequired("target-version") //nolint:errcheck
	rootCmd.AddCommand(grypeConfigCmd)
}

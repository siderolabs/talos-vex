// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/pkg/vexgen"
)

var viewCmd = &cobra.Command{
	Use:   "view",
	Short: "View data about statements to be generated",
	Long: `The view command shows a summary of the statements that will be
	generated in the VEX document for the specified product version.
	Usage: generate-vex view --source-file <path> --target-version <version>`,
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

		table := table.New("Vulnerability", "Status", "Status Notes", "Justification", "Impact", "Action")
		for _, statement := range statements {
			table.AddRow(statement.Vulnerability.Name, statement.Status, statement.StatusNotes, statement.Justification, statement.ImpactStatement, statement.ActionStatement)
		}
		table.Print()
	},
}

func init() {
	viewCmd.Flags().StringVarP(&options.DataFile, "source-file", "", "", "Path to the YAML file containing data for VEX generation")
	viewCmd.Flags().StringVarP(&options.Version, "target-version", "", "", "Version of the VEX document to generate")
	viewCmd.MarkFlagRequired("target-version") //nolint:errcheck
	rootCmd.AddCommand(viewCmd)
}

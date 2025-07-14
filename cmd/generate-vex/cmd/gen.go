// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/internal/pkg/vexgen"
)

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a VEX document",
	Long: `Generate a VEX document,
	Usage: generate-vex gen --source-file <path> --target-version <version>
	Source file should be a YAML file containing exploitability data.
	Target version is the version of the product to generate the VEX document for.`,
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

		// Use SOURCE_DATE_EPOCH as the timestamp
		doc, err := vexgen.Populate(data, options.Version, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error populating VEX document: %s", err)

			return
		}

		err = vexgen.Serialize(doc, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error serializing VEX document: %s", err)

			return
		}
	},
}

func init() {
	genCmd.Flags().StringVarP(&options.DataFile, "source-file", "", "", "Path to the YAML file containing data for VEX generation")
	genCmd.Flags().StringVarP(&options.Version, "target-version", "", "", "Version of the VEX document to generate")
	genCmd.MarkFlagRequired("target-version") //nolint:errcheck
	rootCmd.AddCommand(genCmd)
}

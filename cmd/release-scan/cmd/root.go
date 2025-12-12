// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type Options struct {
	DataFile  string
	Version   string
	Owner     string
	Repo      string
	OutputDir string
}

var options Options

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "release-scan",
	Short: "A CLI for scanning release SBOMs against the current vulnerability info",
	Long:  `Usage: release-scan command`,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

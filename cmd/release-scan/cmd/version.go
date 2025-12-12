// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vex/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints release-scan version.",
	Long:  `Prints release-scan version.`,
	Args:  cobra.NoArgs,
	Run: func(*cobra.Command, []string) {
		line := fmt.Sprintf("%s version %s (%s)", version.Name, version.Tag, version.SHA)
		fmt.Println(line)
	},
}

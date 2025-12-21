// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"

	"github.com/google/go-github/v80/github"
	"github.com/spf13/cobra"

	"github.com/siderolabs/talos-vex/internal/pkg/scanner"
	"github.com/siderolabs/talos-vex/internal/pkg/types/v1alpha1"
	"github.com/siderolabs/talos-vex/pkg/gitversion"
)

func downloadAsset(githubClient *github.Client, owner, repo string, asset github.ReleaseAsset, dir string) (string, error) {
	rc, _, err := githubClient.Repositories.DownloadReleaseAsset(
		context.TODO(),
		owner,
		repo,
		*asset.ID,
		http.DefaultClient,
	)
	if err != nil {
		return "", err
	}

	name := *asset.Name

	f, err := os.OpenFile(
		path.Join(dir, name),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644,
	)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	_, err = io.Copy(f, rc)

	return name, err
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan releases matching the rules",
	Long: `Scan releases matching the rules, using the provided VEX YAML source
	Usage: release-scan scan`,
	Args: cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		err := os.MkdirAll(options.OutputDir, 0o755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output directory %s: %s\n", options.OutputDir, err)

			return
		}

		client := github.NewClient(nil)

		// Use token if provided, for higher limits
		if token, exists := os.LookupEnv("GITHUB_TOKEN"); exists {
			client = client.WithAuthToken(token)
		}

		data, err := v1alpha1.LoadExploitabilityData(options.DataFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading exploitability data file %s: %s\n", options.DataFile, err)

			return
		}

		if err = data.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "error validating exploitability data: %s\n", err)

			return
		}

		sc, err := scanner.NewScanner(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating scanner: %s\n", err)

			return
		}

		defer sc.Close() //nolint:errcheck

		sbomRegex := regexp.MustCompile(options.MatchFiles)
		skipRegex := regexp.MustCompile(options.SkipTags)

		if skipRegex.MatchString(options.StartVersion) {
			fmt.Fprintf(os.Stderr, "Start version %s is in ignore regex\n", options.StartVersion)

			return
		}

		page := 0
		for {
			releases, result, err := client.Repositories.ListReleases(context.TODO(), options.Owner, options.Repo, &github.ListOptions{PerPage: 100, Page: page})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error fetching releases: %s\n", err)

				return
			}

			done := false

			for _, release := range releases {
				ver := release.GetTagName()

				cmp := gitversion.CompareVersions(ver, options.StartVersion)
				if cmp < 0 || skipRegex.MatchString(ver) {
					continue
				}

				dir := path.Join(options.OutputDir, ver)
				sbomFiles := []string{}

				err := os.MkdirAll(dir, 0o755)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error creating version workdir: %s\n", err)

					continue
				}

				fmt.Println("Scanning version:", ver)

				for _, asset := range release.Assets {
					if !sbomRegex.MatchString(*asset.Name) {
						continue
					}

					fmt.Println("- downloading", *asset.Name)
					sbomFilename, err := downloadAsset(client, options.Owner, options.Repo, *asset, dir)
					if err != nil {
						fmt.Fprintf(os.Stderr, "error downloading %s: %s\n", *asset.Name, err)

						continue
					}

					sbomFiles = append(sbomFiles, sbomFilename)
				}

				if err := sc.ScanRelease(ver, dir, sbomFiles); err != nil {
					fmt.Fprintf(os.Stderr, "Scan failed: %s\n", err)

					break
				}

				// GitHub returns releases ordered from newest to oldest, therefore we're done when reached the oldest scanned version
				if cmp == 0 {
					done = true

					break
				}
			}

			if done {
				break
			}

			page = result.NextPage
		}
	},
}

func init() {
	scanCmd.Flags().StringVarP(&options.DataFile, "source-file", "", "", "Path to the YAML file containing data for VEX generation")
	scanCmd.Flags().StringVarP(&options.StartVersion, "start-version", "", "v1.11.0", "Minimum version that should be scanned")
	scanCmd.Flags().StringVarP(&options.Owner, "owner", "o", "siderolabs", "GitHub repo owner")
	scanCmd.Flags().StringVarP(&options.Repo, "repo", "r", "talos", "GitHub repo to get releases from")
	scanCmd.Flags().StringVarP(&options.OutputDir, "output-dir", "O", "_out", "Directory to save results to")
	// At least currently SBOMs are not arch-dependent
	scanCmd.Flags().StringVarP(&options.MatchFiles, "match", "m", ".*\\-arm64.spdx\\.json$", "Regex for SBOM files to scan in each release")
	scanCmd.Flags().StringVarP(&options.SkipTags, "skip", "", "(alpha|beta|rc)", "Regex of versions to skip (e.g. unsupported prereleases)")
	rootCmd.AddCommand(scanCmd)
}

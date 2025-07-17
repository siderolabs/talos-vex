# Talos Vulnerability Exploitability eXchange

[OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) is a standard for communicating the exploitability of vulnerabilities of components in a software product.
This repository contains such information for [Talos Linux](https://github.com/siderolabs/talos), as well as the tool we maintain to generate VEX documents for different versions and editions of Talos.

## Usage

VEX document for the corresponding version can be used to aid vulnerability scanning and management by hiding vulnerabilities that are not exploitable in a particular software version or edition.

Grype is one of the tools that can make use of OpenVEX documents:

```bash
grype sbom:./talos-arm64.spdx.json --vex ./talos.vex.json
```

This command will show that some of the vulnerabilities are found, but listed as `ignored` due to the VEX document containing statements indicating they are not exploitable in the given version of Talos.

Other security tools might also support OpenVEX documents, or VEX documents of other formats such as CSAF 2.0.
Passing the VEX document to such tools will allow them to filter vulnerabilities and possibly suggest mitigations for the vulnerabilities that have advisories listed in the VEX document.

## Generating VEX documents

To build a VEX document for a specific version of Talos, use the `generate-vex` tool from this repository.

The easiest approach is to use the latest container image, which contains a built-in data about Talos vulnerability statuses:

```bash
podman run -e SOURCE_DATE_EPOCH=1 --rm ghcr.io/siderolabs/generate-vex:latest gen --target-version v1.11.0-alpha.3 | tee talos.vex.json
```

SOURCE_DATE_EPOCH is accepted by the tool to ensure reproducibility of the generated VEX document, else the current date will be used.

You can pass your own data file with the `--source-file` flag, which should be a YAML file containing the vulnerability data in the OpenVEX format.
The tool will then generate a VEX document for the specified version of Talos.

## Previewing VEX entries

To preview the VEX entries for a specific version as a table (also works for own data files), you can use the `view` command.
This is useful when editing VEX data or when you want to quickly check the status of vulnerabilities for a specific version of Talos.

```bash
docker run --rm -v $(pwd):/data ghcr.io/siderolabs/generate-vex:latest view --source-file /data/internal/pkg/types/v1alpha1/data/talos.yaml --target-version v1.11.0
```

## Updating databases and generating VEX documents

This section is mostly relevant for maintainers of Talos, but you are welcome to make use of the tool to manage VEX data for your own projects, managing exploitability data in the same way.

Format is based on the OpenVEX specification, but in a YAML format for easier editing and comment support.
Additionally, the tool accepts `from` and `to` versions to specify the first and last versions of the product that the statement applies to, which allows to generate all the statements from a single data file spanning all supported series.

Here is an example file with some comments:

```yaml
# Author to be added to the VEX document
author: "Sidero Labs (https://siderolabs.com/)"
# ID without a version
ids:
  purl: pkg:generic/talos
  cpe23: cpe:2.3:o:siderolabs:talos
# A list of all statements
statements:
  - created: 2025-07-14T12:00:00Z # Date to be listed for the statement
    name: "CVE-0000-1234" # Main name
    description: "In a library X, a vulnerability was found that allows for arbitrary code execution." # Human-readable description
    aliases: # Aliases for the vulnerability, such as CVE IDs
      - "GHSA-0000-1234"
    from: v1.10.0-alpha.1-35-g46d67fe44 # First version this statement applies to
    to: v1.11.0-alpha.0 # Last version this statement applies to
    # Status of the vulnerability, such as not_affected, affected, fixed, under_investigation
    status: "fixed"
    # Human-readable notes about the status
    statusNotes: "Applied a patch by the library author to fully mitigate the issue, commit 1234abc"
  - created: 2025-07-14T13:41:23Z
    name: "CVE-2025-40014"
    # either to, from or both can be omitted if no lower or upper bound is applicable
    from: v1.4.0-alpha.0-16-g683b4ccb4
    status: "not_affected"
    statusNotes: |
      Talos kernel configurations do not enable the affected driver in any build
      https://github.com/siderolabs/pkgs/blob/8ed84c56c384c957940b1b2371dd0c4fb1a80d54/kernel/build/config-amd64#L3491
      https://github.com/siderolabs/pkgs/blob/8ed84c56c384c957940b1b2371dd0c4fb1a80d54/kernel/build/config-arm64#L4024
    # not_affected statements MUST include an allowed justification value
    justification: "vulnerable_code_not_present"
```

Please refer to the following parts of the OpenVEX specification for more details on the fields:

- [Statement Fields](https://github.com/openvex/spec/blob/50abcfe257f1fc36ded2a17cc78e25821958cca2/OPENVEX-SPEC.md#statement-fields)
- [Status Labels](https://github.com/openvex/spec/blob/50abcfe257f1fc36ded2a17cc78e25821958cca2/OPENVEX-SPEC.md#status-labels)
- [Status Justifications](https://github.com/openvex/spec/blob/50abcfe257f1fc36ded2a17cc78e25821958cca2/OPENVEX-SPEC.md#status-justifications)

Also, currently applicable struct fields can be found [in the code](https://github.com/siderolabs/talos-vex/blob/main/internal/pkg/types/v1alpha1/v1alpha1.go).

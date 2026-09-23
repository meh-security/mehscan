# Install Mehscan on Windows, Linux, or macOS

Linux/macOS use `scripts/install-mehscan.sh`, a Bash entry point with a Python
3.9+ standard-library helper for bounded HTTPS, JSON, and ZIP validation. No
PowerShell, pip packages, `jq`, or separate unzip tool is needed. Windows uses
`scripts/install-mehscan.ps1` with PowerShell 7 (`pwsh`). Both verified release
installers require GitHub CLI (`gh`) with `attestation verify`. Mehscan itself
needs none of these tools after installation.
Installing or upgrading prerequisites changes the host; use an existing
installation where possible and follow the user's host-management preferences.

## Why recommend GitHub CLI, and what if it is unavailable?

We recommend `gh` for release installation because its attestation verifier
checks the archive's build provenance against the expected repository, signer
workflow, source tag, and hosted-runner policy. Known releases also enforce the
skill's source commit pin. A checksum alone cannot establish those facts: an
archive and its checksum file could both have been replaced. The installer
uses GitHub CLI's maintained verifier and trusted Sigstore roots rather than
implementing signature verification itself. See the
[GitHub verifier documentation](https://cli.github.com/manual/gh_attestation_verify).

GitHub CLI is recommended for this installation path, not a dependency of the
scanner. Handle missing or outdated `gh` in this order:

1. Recommend installing or upgrading `gh` using the platform instructions below
   if host setup is suitable, then retry the verified release installer.
2. Otherwise, when an existing trusted Mehscan checkout and Rust/native build
   toolchain are available and building is within scope, follow
   [Build without PowerShell or GitHub CLI](#build-without-powershell-or-github-cli).
   Check the built binary's version and use its absolute path.
3. If neither path is available, report that Mehscan could not be installed and
   name the missing verifier or source-build prerequisites.

The agent selects this fallback; the installer never automatically builds from
source or weakens verification. Failed provenance verification also prohibits
executing the downloaded archive. Building a separate trusted checkout is still
possible within scope, but does not make that rejected archive trustworthy.

## Release targets

The release workflow currently builds these assets. The installer checks the
actual release for an exact match and never substitutes another architecture.

| Host | Release target |
| --- | --- |
| Windows x64 | `windows-x86_64` |
| Linux x64 | `linux-x86_64` |
| macOS Intel | `macos-x86_64` |
| macOS Apple Silicon | `macos-aarch64` |

Linux ARM64 and Windows ARM64 do not currently have native release assets.
Linux x64 binaries are built on Ubuntu 24.04; this does not promise compatibility
with every Linux distribution, older glibc, or musl-based systems such as Alpine.
Use a source build on a compatible toolchain when a release binary cannot run.

## Prerequisites

On every platform, first look up `mehscan` on `PATH` and check `--version`.
If available, reuse its absolute path and skip all installation prerequisites.
An explicit version mismatch, failed version check, or source-provenance request
that cannot be satisfied stops with an explanation; it does not trigger an
implicit installation. Only explicitly requested reinstallation uses
`--force-download` (Windows: `-ForceDownload`). The Bash entry point performs
this lookup before requiring Python, and neither installer needs `gh` to reuse
an existing executable. The PowerShell installer accepts Windows only.

GitHub CLI officially supports Linux, macOS, and Windows. macOS installation
uses `brew install gh`; Linux offers official apt and RPM repositories.
GitHub also provides [precompiled binaries](https://github.com/cli/cli/releases)
for both platforms when a package manager is unavailable. See the
[official installation options](https://github.com/cli/cli#installation).
Use a current `gh` version supporting the installer's attestation options;
an outdated distribution package may need upgrading. `gh auth login` is not
required for Mehscan's public downloads and local-bundle verification.

### macOS

With an existing Homebrew installation:

```sh
brew install python gh
```

Use an existing Python 3.9+ installation if available; otherwise install
Python and `gh`. GitHub CLI documents [macOS installation](https://github.com/cli/cli#installation).

### Linux

Use your distribution's Bash and Python 3.9+ packages and GitHub CLI's
[official Linux package instructions](https://github.com/cli/cli/blob/trunk/docs/install_linux.md).
For example, on Ubuntu, configure GitHub CLI's signed apt repository using
those instructions, then install the packages:

```sh
sudo apt-get update
sudo apt-get install bash python3 gh
```

These commands assume the GitHub CLI repository is already configured. Do not use
Ubuntu repository instructions on another distribution, or assume a
distribution's older `gh` package supports the required verification options.
If installing the prerequisites is unsuitable, use the source-build option below.

### Windows

Use [PowerShell 7 installation instructions](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows)
and [GitHub CLI installation instructions](https://github.com/cli/cli#installation).
The built-in Windows PowerShell 5.1 (`powershell.exe`) is not supported.
Open a new terminal if needed so both tools are on `PATH`.

On Linux/macOS, check prerequisites before requesting a release download:

```text
python3 --version
gh attestation verify --help
```

On Windows, check `pwsh --version` and `gh attestation verify --help` instead.
Each installer checks `gh` again and stops if verification fails. The
[GitHub verifier documentation](https://cli.github.com/manual/gh_attestation_verify)
describes its policies. Do not bypass a missing or outdated verifier with a
checksum-only download.

## Run the release installer

Run from the skill directory, including its `scripts` and `references` folders.
In a repository checkout this is `skills/mehscan-security`; in an installed
skill, use that skill's actual directory. Do not copy just the installer: it
also needs the bundled helper (`install-mehscan.py` for Bash,
`public-download.ps1` for PowerShell) and `references/release-pins.json`.

From Bash or Zsh on Linux/macOS:

```sh
if mehscan_bin=$(bash ./scripts/install-mehscan.sh); then
    "$mehscan_bin" --version
    "$mehscan_bin" --help
fi
```

From PowerShell 7 on Windows:

```powershell
$mehscanBin = & ./scripts/install-mehscan.ps1
& $mehscanBin --version
& $mehscanBin --help
```

Omitting `--version` (PowerShell: `-Version`) selects the latest release when
installation is necessary. Append `--version 0.6.1` only when that release was
requested; append `--install-directory PATH` for a requested destination
(PowerShell: `-InstallDirectory PATH`). Use `--force-download` to bypass reuse
of an existing binary on `PATH` only for explicitly requested reinstallation
(PowerShell: `-ForceDownload`).
`--source-digest COMMIT` requires an exact version and an independently trusted
source commit (PowerShell: `-SourceDigest COMMIT`). Source commit pinning and
failure handling remain as specified in [the skill](../SKILL.md).

The default installation location is
`~/.mehscan/cli/<tag>/<platform>-<architecture>/`. On Linux/macOS the installer
sets executable permissions and attempts a managed symlink in
`~/.local/bin/mehscan`, preserving unrelated entries. That directory may not be
on `PATH`; use the returned absolute executable path during the current task.
Windows installations also return an absolute path and do not require a global
`PATH` change. Do not run the Mehscan installer with `sudo`.

## Build without PowerShell or GitHub CLI

From an existing trusted Mehscan source checkout, with Rust 1.88 or newer and
the host's native C/C++ build tools available:

```text
cargo build -p mehscan-cli --release --locked
```

On Linux/macOS:

```sh
./target/release/mehscan --version
./target/release/mehscan --help
```

On Windows, run `./target/release/mehscan.exe` instead. Use the built binary's
absolute path for subsequent scans. A source build uses the trusted checkout;
it is not verification of a downloaded release archive. Only build when a
Mehscan checkout is available and building is within the authorized task.

## Installer options considered

The Unix Bash entry point invokes a Python standard-library helper, removing
PowerShell from Linux/macOS setup while avoiding fragile shell parsing of ZIP
metadata and JSON. The Windows PowerShell installer remains available.
Both implementations enforce the same provenance policies, source pins,
download limits, archive membership, manifest, and binary-version checks;
the release CI runs their contract tests on the corresponding hosts.
Native package-manager distribution could improve setup later, but no Mehscan
Homebrew formula or Linux package is provided by this repository today.
Source building remains the fallback that avoids both release installers and `gh`.

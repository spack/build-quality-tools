#!/usr/bin/env python3
"""For reviewing pull requests, run `spack install` on recipes changed current PR

Important TODO:
run spack maintainers to check for maintainers of the packages.
Only attempt to merge if the maintainers approved merging the PR.

Important TODO:
- if the rebase to develop fails, merge develop into the branch and push the branch.

Important TODO:
Limit the amount of builds, in some, the amount of variants can be hundreds.
"""
# Copyright 2024, Bernhard Kaindl
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from io import BytesIO
from glob import glob
from logging import INFO, basicConfig, info
from pathlib import Path
from shutil import which
from subprocess import getoutput
from typing import Any, Dict, List, Tuple, TypeAlias

try:
    import pexpect
except ImportError:
    print("pexpect missing, please run:")
    print("sudo apt-get -y install python3-pexpect || pip3 install pexpect")
    sys.exit(1)


ExitCode: TypeAlias = int
Success: ExitCode = 0


def get_os_info() -> Tuple[str, str, str]:
    """Get the OS information."""
    about_build_host = ""
    os_name = ""
    os_version_id = ""
    with open("/etc/os-release", encoding="utf-8") as f:
        os_release = f.read()
        for line in os_release.split("\n"):
            if line.startswith("PRETTY_NAME="):
                about_build_host += " on " + line.split("=")[1].strip().strip('"')
            if line.startswith("VERSION_ID="):
                os_version_id = line.split("=")[1].strip().strip('"')
            if line.startswith("NAME="):
                os_name = line.split("=")[1].strip().strip('"')
    return about_build_host, os_name, os_version_id


class LogFile:
    """Context manager that copies written data and any exceptions to a log file."""

    def __init__(self, filename):
        self.file = open(filename, "w", encoding="utf-8")  # pylint: disable=consider-using-with

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is not None:
            self.file.write(traceback.format_exc())
        self.file.close()

    def write(self, data: bytes | str):  # pexpect sends bytes
        """Write the data to the file and stdout."""
        if not isinstance(data, str):
            data = data.decode("utf-8", errors="replace")
        self.file.write(data)

    def flush(self):
        """Flush the file and stdout."""
        self.file.flush()


def spawn(command: str, args, logfile=None) -> ExitCode:
    """Spawn a command with input and output passed through, with a pyt and exit code."""

    print("Command:", " ".join([command, *args]))
    child = pexpect.spawnu(command, args, timeout=1800)  # 1800 is 30 minutes
    if logfile:
        child.logfile_read = logfile

    window_size = os.get_terminal_size()
    child.setwinsize(window_size.lines, window_size.columns)

    def change_window_size_signal_passthrough(_, __):
        """Pass the SIGWINCH signal through to the child."""
        window_size = os.get_terminal_size()
        if not child.closed:
            child.setwinsize(window_size.lines, window_size.columns)

    signal.signal(signal.SIGWINCH, change_window_size_signal_passthrough)

    # Disabled as it blocks interrupting the process:
    # def filter_suspended_output(data: bytes) -> bytes:
    #     """Filter out suspend output(Ctrl-Z), which stops output but isn't resumed properly"""
    #     if b"\x1a" in data:
    #         print("\nUse Ctrl-S to stop output, and Ctrl-Q to resume instead of Ctrl-Z.")
    #     return data.replace(b"\x1a", b"")

    cwd = f"{os.getcwd()}/".encode()

    def filter_output(data: bytes) -> bytes:
        """Filter out the output."""
        # remove '-DCMAKE_.*:STRING=<any text>' from the output:
        data = re.sub(b"'-DCMAKE_.*:STRING=.*'", b"", data)
        # remove extra consecutive :: from the output:
        data = re.sub(b":+", b":", data).replace(b"           :", b"")
        # remove the current working directory and empty lines from the output:
        return data.replace(cwd, b"").replace(b"\n:\n", b"\n").replace(b"\n\n", b"\n")

    child.interact(
        # The type annotation is wrong in pexpect, it should be str | None, not str:
        escape_character=None,  # type:ignore # pyright: ignore[reportArgumentType]
        # The type annotation is wrong in pexpect, it should be func(bytes) -> bytes:
        # input_filter=filter_suspended_output,  # type:ignore
        output_filter=filter_output,  # type:ignore
    )

    child.expect(pexpect.EOF)
    child.close()
    return int(child.exitstatus or 0)


def update_apt_package_cache() -> ExitCode:
    """Update the apt package cache"""

    # Install the needed packages on Debian/Ubuntu.
    # If /var/cache/apt/pkgcache.bin older than 24 hours, update the package list.
    if os.path.exists("/var/cache/apt/pkgcache.bin"):
        if os.path.getmtime("/var/cache/apt/pkgcache.bin") < time.time() - 86400:
            error = spawn("sudo", ["apt-get", "-y", "update"])
            if error:
                print("Failed to update the package list.")
                return error
    return Success


def install_github_cli_from_github_debian_repo() -> ExitCode:
    """Install the GitHub CLI from the GitHub repository."""

    ring = "/etc/apt/trusted.gpg.d/githubcli-archive-keyring.gpg"
    if not os.path.exists(ring):
        # The keyring is used to verify the GitHub CLI repository.
        exit_code = spawn(
            "sudo",
            [
                "wget",
                "https://cli.github.com/packages/githubcli-archive-keyring.gpg",
                "-O",
                "/etc/apt/trusted.gpg.d/githubcli-archive-keyring.gpg",
            ],
        )
        if exit_code:
            print("Failed to download the GitHub CLI keyring.")
            return exit_code

    sources = "/etc/apt/sources.list.d/github-cli.list"
    if not os.path.exists(sources):
        # save the repo configuration to a temporary file:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            arch = subprocess.getoutput("dpkg --print-architecture")
            tmp.write(
                f"deb [arch={arch} signed-by={ring}]"
                " https://cli.github.com/packages stable main\n".encode()
            )

        # Move the temporary file to the final location:
        exit_code = spawn("sudo", ["mv", "-v", tmp.name, sources])
        if exit_code:
            print("Failed to create the GitHub CLI repository configuration.")
            return exit_code

    # Update the package list:
    exit_code = spawn("sudo", ["apt-get", "update"])
    if exit_code:
        print("Failed to update the package list.")
        return exit_code

    # Install the GitHub CLI:
    exit_code = spawn("sudo", ["apt-get", "install", "-y", "gh"])
    if exit_code:
        print("Failed to install the optional tooling packages.")
        return exit_code

    return spawn("sudo", ["apt", "update"])


def install_spack_dependencies_on_debian() -> ExitCode:
    """Install the dependencies of Spack."""

    # Set the environment variables to avoid some interactive prompts
    os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    os.environ["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
    os.environ["APT_LISTCHANGES_FRONTEND"] = "none"
    os.environ["APT_LISTBUGS_FRONTEND"] = "none"
    os.environ["NEEDRESTART_SUSPEND"] = "y"
    os.environ["NEEDRESTART_MODE"] = "l"

    update_apt_package_cache()

    # Remove needrestart: It inserts a prompt during package installation.
    exitcode, output = subprocess.getstatusoutput("dpkg-query -l needrestart")
    if exitcode == 0 and "\nii" in output:
        print("Removing needrestart to avoid prompts during package installation.")
        spawn("sudo", ["apt-get", "remove", "-y", "needrestart"])

    # Install the required packages and recommended packages for spack
    optional_tools = [
        "git",  # Version control system
        "bzip2",  # Compression tool
        "unzip",  # Unzip tool
        ("build-essential", "make"),  # Build tools
        "clang",  # C/C++ compiler
        ("llvm-dev", "llvm-config"),  # llvm-config is needed for building mesa
        "curl",  # Download tool
        "wget",  # Download tool
        "fzf",  # Fuzzy finder for the shell and the GitHub CLI commands/aliases
        "pipx",  # Python package manager for tools like pre-commit and black
        ("python3-pip", "pip3"),  # Python package manager
    ]
    tools = []
    for tool in optional_tools:
        if isinstance(tool, tuple):
            if not which(tool[1]):
                tools.append(tool[0])
        elif isinstance(tool, str):
            if not which(tool):
                tools.append(tool)
    if tools:
        exit_code = spawn("sudo", ["apt-get", "install", "-y", *tools])
        if exit_code:
            print("Failed to install the optional tooling packages.")
            return exit_code

    exit_code = install_github_cli_from_github_debian_repo()
    if exit_code:
        return exit_code

    # Use pipx to install the latest versions of pre-commit and black:
    for tool in ["pre-commit", "black"]:
        if not which(tool):
            exit_code = spawn("pipx", ["install", tool])
            if exit_code:
                print(f"Failed to install the latest version of {tool}.")
                return exit_code

    # If the distribution is new enough to have newer compilers, install them.
    about_build_host, os_name, os_version_id = get_os_info()

    print("Running", about_build_host)
    if os_name == "Ubuntu" and os_version_id >= "22.04":
        return install_spack_dependencies_on_ubuntu_22_04_or_newer()
    return Success


def install_spack_dependencies_on_ubuntu_22_04_or_newer() -> ExitCode:
    """Install the dependencies of Spack on Ubuntu 22.04 or newer."""
    # Install additional compilers for building the packages with Spack.

    if not glob("/etc/apt/sources.list.d/ubuntu-toolchain-r-ubuntu-test-*.list"):
        # Add the Ubuntu toolchain repository for newer compilers like gcc-13 on Ubuntu 22.04.
        error = spawn("sudo", ["add-apt-repository", "-y", "ppa:ubuntu-toolchain-r/test"])
        if error:
            print("Failed to add the Ubuntu toolchain repository.")
            return error

    compilers = []
    for version in ["13", "12", "11", "10", "9"]:
        for tool in ["g++", "gfortran"]:
            program = tool + "-" + version
            if not which(program):
                compilers.append(program)

    if compilers:
        error = spawn("sudo", ["apt-get", "install", "-y", *compilers])
        if error:
            print("Failed to install the additional compilers.")
            return error

    return Success


def install_spack_dependencies() -> ExitCode:
    """Install the dependencies of Spack."""
    # Check the Linux distribution and install the needed packages.
    # Check if /etc/debian_version exists.
    if os.path.exists("/etc/debian_version"):
        return install_spack_dependencies_on_debian()

    # Add support for other distributions here.

    print("Unsupported Linux distribution (not Debian/Ubuntu), please install the dependencies.")

    # Check if the system has the needed compilation tools for spack installed.
    version_checks = ["git", "gfortran", "make", "patch", "bzip2"]

    missing_tools = print_missing_tools(version_checks)
    if missing_tools:
        print("Please install the missing packages:", missing_tools)
        return 5
    if print_version_checks(version_checks):
        return 6

    return Success


def print_missing_tools(version_checks):
    """Print the missing tools."""
    missing_tools = []
    for tool in version_checks:
        ret, _, __ = run(["which", tool])
        if ret:
            missing_tools.append(tool)
    return missing_tools


def print_version_checks(version_checks):
    """Print the versions of the tools."""
    for tool in version_checks:
        output, err = pexpect.run(tool + " --version", encoding="utf-8", withexitstatus=True)
        if err:
            print("Failed to run", tool, " --version")
            return err
        print(tool + ":", output.splitlines()[0])
    return Success


def gh_cli_auth_info() -> Tuple[ExitCode, str]:
    """Get the GitHub CLI authentication information."""
    return subprocess.getstatusoutput("gh auth status")


def get_github_user() -> str:
    """Get the GitHub user name."""

    exitcode, out = gh_cli_auth_info()
    if exitcode:
        return ""
    # Extract "user" from "Logged in to github.com as user ("config")"
    user_match = re.search(r"Logged in to github.com (\w+) (\w+)", out)
    if not user_match:
        print("Failed to get the GitHub user name.")
        return ""
    return user_match.group(2)


def authenticate_github_cli() -> ExitCode:
    """Authenticate with GitHub, paste the URL in a browser, and paste the one-time code."""

    if not which("gh"):  # Don't block use in containers without GitHub CLI using -b <spec>
        return Success

    # Check if the user is already authenticated with GitHub.
    exitcode, out = gh_cli_auth_info()
    if exitcode == Success:
        return Success

    print(out)

    # Authenticate with GitHub.
    print("Please authenticate with GitHub:")
    error = spawn("gh", ["auth", "login"])
    if error:
        print("Failed to authenticate with GitHub.")
        return error

    print("Successfully authenticated with GitHub.")
    return Success


def setup_github_cli_dashboard(build_tools_dir) -> ExitCode:
    """Set up the GitHub CLI dashboard."""
    error = authenticate_github_cli()
    if error:
        return error

    # Install the GitHub CLI dash extension
    if "dlvhdr/gh-dash" not in pexpect.run("gh extension list", encoding="utf-8"):
        error = spawn("gh", ["extension", "install", "dlvhdr/gh-dash"])
        if error:
            print("Failed to install the GitHub CLI dash extension.")
            return error

    # Check if the GitHub CLI dashboard is set up.
    dash_config = Path(Path.home(), ".config", "gh-dash", "config.yml")
    if not os.path.exists(dash_config):
        dash_config.parent.mkdir(parents=True, exist_ok=True)
        # Copy the config file from the build_tools_dir to the ~/.config/gh-dash directory.
        dash_config.write_bytes(Path(build_tools_dir, "gh-dash", "config.yml").read_bytes())
        print("Configured the GitHub CLI dashboard.")
    else:
        print("GitHub CLI dashboard is already configured, see:", dash_config)

    print("To use the GitHub CLI dashboard, run: gh dash")
    return Success


def bootstrap_spack() -> ExitCode:
    """Bootstrap the host and Spack"""
    if install_spack_dependencies():
        return True
    # Check if the Spack repository is cloned.
    if not os.path.exists("bin/spack") and os.path.isdir("spack"):
        os.chdir("spack")

    if not os.path.exists("bin/spack") and os.path.isdir(os.path.expanduser("~/spack")):
        os.chdir(os.path.expanduser("~/spack"))

    if not os.path.exists("bin/spack"):
        os.chdir(os.path.expanduser("~"))
        print("Spack is not found, cloning the Spack git repository from GitHub.")
        error = spawn("git", ["clone", "https://github.com/spack/spack.git"])
        if error:
            print("Failed to clone the Spack repository.")
            return error
        os.chdir("spack")

    build_tools_dir = os.path.dirname(__file__)

    # Install the pre-commit hook for the build-quality checks repository for contributors.
    err, _, __ = run(["which", "pre-commit"])
    if not err:
        # Install the pre-commit hook for the build-quality checks repository.
        # Is not os-agnostic yet, as it uses the shell:
        spawn("sh", ["-c", f"cd {build_tools_dir} && pre-commit install"])

    err = setup_github_cli_fzf_aliases()
    if err:
        return err

    return setup_github_cli_dashboard(build_tools_dir)


def setup_github_cli_fzf_aliases() -> ExitCode:
    """Set up the fzf fuzzy finder for the shell and the GitHub CLI commands/aliases."""

    exitcode, _, __ = run(["which", "fzf"])
    if exitcode:
        print("fzf is not installed, please install it.")
        return exitcode

    # Set up the GitHub CLI aliases for checking out PRs:
    exitcode = spawn(
        "gh",
        [
            "alias",
            "set",
            "--clobber",
            "co",
            "--shell",
            'id="$(gh pr list -L60|fzf|cut -f1)"; [ -n "$id" ] && gh pr checkout "$id"',
        ],
    )
    if exitcode:
        return exitcode
    return spawn(
        "gh",
        [
            "alias",
            "set",
            "--clobber",
            "review",
            "--shell",
            'id="$(gh pr list -L20 -S "review:required draft:false no:assignee'
            " -status:failure -label:changes-requested -label:waiting-on-maintainer"
            ' -label:waiting-on-dependency"|fzf|cut -f1)"; [ -n "$id" ]'
            " && gh pr checkout $id && gh pr view -c && gh pr diff",
        ],
    )


def get_safe_versions(spec):
    """Find the safe versions of the specs. Parse the output of `bin/spack versions --safe`:
    bin/spack versions --safe wget
    ==> Safe versions (already checksummed):
    master  2.4.1  2.3  2.2  2.1  2.0  1.3
    """
    safe_versions = []
    # FIXME: The spec may contain variants, etc, use a regex to remove them.
    recipe = spec.split("+")[0]  # Remove variants, and more as they are added to the spec.
    err, stdout, _ = run(["bin/spack", "versions", "--safe", recipe])
    if err == 0:
        for line in stdout.split("\n"):
            if line.startswith("==> Safe versions"):
                continue
            safe_versions.extend(line.split())

    # Remove the versions that should be skipped (development branches often fail to build):
    for skip_version in ["master", "develop", "main"]:
        if skip_version in safe_versions:
            safe_versions.remove(skip_version)

    return safe_versions


def find_already_installed(specs_to_check: List[str]) -> Tuple[List[str], List[str]]:
    """List the installed packages."""
    installed = []
    findings = []

    for spec in specs_to_check:
        print(f"Checking if {spec} is already installed:")
        err, stdout, _ = run(
            ["bin/spack", "find", "--no-groups", "--show-full-compiler", "-v", "-I", spec]
        )
        if err == 0:
            print(stdout)
            installed.append(spec)
            findings.append(stdout.replace(" build_system=python_pip", ""))

    return installed, findings


def spack_uninstall_packages(installed):
    """Uninstall the installed packages."""
    for recipe in installed:
        ret, out, err = run(["bin/spack", "uninstall", "-ya", "--dependents", recipe])
        print(out)
        if ret != 0:
            print(err or out)
            sys.exit(ret)


def run(command: List[str] | str, check=False, show_command=False) -> Tuple[int, str, str]:
    """Run a command and return the output."""
    if isinstance(command, str):
        command = command.split()
    if show_command:
        print(" ".join(command))
    cmd: subprocess.CompletedProcess[str] = subprocess.run(
        command, check=check, text=True, capture_output=True, timeout=240
    )
    return cmd.returncode, cmd.stdout.strip(), cmd.stderr.strip()


def check_for_recipe(line, changed_files, changed_recipe, recipes):
    """Check if the line is a path to a changed file."""

    changed_path = re.search(r"\+\+\+ b/(.*)", line)
    if changed_path:
        changed_file = changed_path.group(1)
        changed_files.append(changed_file)
        recipe = re.search(r"var/spack/repos/builtin/packages/(.*)/package.py", changed_file)
        if recipe:
            changed_recipe[0] = recipe.group(1)
            recipes.append(changed_recipe[0])
        else:
            changed_recipe[0] = ""


def add_bool_variant(variant, new_variants, line):
    """Check the variant default and add boolean variants to the list of new variants"""

    default = re.search(r"default=(\w+)", line)
    # Check the line for "default=False" or "default=True" and if it is a boolean variant:
    if default and default.group(1) in ("True", "False"):
        # add the variant to the list of new variants:
        new_variants.append(variant.group(1))


# Of course, this diff parser is not perfect, and should be a class, but it's a start.
def get_specs_to_check(args) -> List[str]:
    """Check if the current branch is up-to-date with the remote branch.

    Check if the current branch is up-to-date with the remote branch.
    On errors and if not up-to-date, return an error exit code.
    """
    changed_files: List[str] = []
    recipe: List[str] = [""]
    recipes: List[str] = []
    specs: List[str] = []
    new_variants: List[str] = []
    new_versions: List[str] = []
    default_versions = new_versions
    deprecated: List[str] = []
    next_line_is_version = False
    next_line_is_variant = False
    version_match = None
    multiline_variant = None

    # The most reliable way to get the PR diff is to use the GitHub CLI:
    err, stdout, stderr = run(["gh", "pr", "diff"])
    if err or stderr:
        print(stderr or stdout)
        sys.exit(err)

    for line in stdout.split("\n"):
        if line.startswith("diff --git"):
            add_recipe_variant_version(specs, recipe, new_variants, new_versions, deprecated)
            next_line_is_version = False
            next_line_is_variant = False
            default_versions = new_versions
            version_match = None
            multiline_variant = None
            continue
        if line[0] != "+":
            continue

        check_for_recipe(line, changed_files, recipe, recipes)
        if not recipe[0]:
            continue

        if multiline_variant:
            add_bool_variant(variant, new_variants, line)
            if "    )" in line:
                multiline_variant = None
            continue

        # Get the list of new and changed versions from the PR diff:
        version_start = re.search(r"    version\($", line)  # version(
        if version_start:
            next_line_is_version = True
            continue
        if next_line_is_version:
            version_match = re.search(r'"([^"]+)"', line)
            next_line_is_version = False
            continue
        if "        deprecated=True," in line and version_match:
            deprecated.append(version_match.group(1))
            print("Deprecated versions:", deprecated)
            version_match = None
            continue
        if version_match and "    )" in line:
            default_versions.append(version_match.group(1))

        if "with default_args(deprecated=True):" in line:
            default_versions = deprecated

        version = re.search(r'    version\("([^"]+)", ', line)  # version("version",
        if version:
            default_versions.append(version.group(1))
            continue

        # Get the list of new or changed variants from the PR diff:
        # TODO: Add support for multi variants/variants with values
        # search for variant( where on its own line, and then search for the variant name.
        variant_start = re.search(r"    variant\($", line)  # variant(
        if variant_start:
            next_line_is_variant = True
            continue
        variant = re.search(r'    variant\("([^"]+)", ', line)  # variant("name",
        if next_line_is_variant or variant:
            variant = variant or re.search(r'"([^"]+)"', line)
            if variant:
                if next_line_is_variant:
                    multiline_variant = variant
                    next_line_is_variant = False
                add_bool_variant(variant, new_variants, line)
            continue

    add_recipe_variant_version(specs, recipe, new_variants, new_versions, deprecated)

    if args.verbose:
        print("Changed files:", changed_files)
        print("Changed recipes:", recipes)
        print("Specs to check:", specs)
    return specs


def merge_variants(changed_recipe, variant, default_variants):
    """Merge the variants with the recipe and return the recipe with the variants."""

    default_variants_disable = "".join(["~" + variant for variant in default_variants])
    recipe_with_variants = changed_recipe[0] + default_variants_disable

    if variant in default_variants:
        # If the variant is in the default variants, remove it from the spec:
        recipe_with_variants = recipe_with_variants.replace("~" + variant, "")
    else:
        # Add the variant to the recipe:
        recipe_with_variants += f"{variant}" if variant.startswith("~") else f"+{variant}"

    return recipe_with_variants


def add_recipe_variant_version(specs, changed_recipe, new_variants, new_versions, deprecated):
    """Add the recipe, variants, and versions to the specs to check."""
    if not changed_recipe[0]:
        return

    variants = {}
    if new_variants:
        ret, variants = parse_variant_infos(changed_recipe[0])
        if ret:
            print("Error getting variants of", changed_recipe[0])
            # return

    # Add the recipe with the default variants disabled (that are true) to the specs to check:
    # If the recipe has no variants, add the recipe without variants.
    # Get the list of variants that are true by default:
    default_variants = [variant for variant, value in variants.items() if value == "true"]
    # Prepend ~ to all default variants to disable them.
    default_variants_disable = "".join(["~" + variant for variant in default_variants])

    # Add the matrix of variants and versions to the specs to check:
    if new_variants and new_versions:
        # Add the recipe with the default variants disabled (that are true) to the specs to check:
        # print("Adding recipe with variants and versions:", changed_recipe[0])
        # print("Variants:", new_variants)
        # print("Versions:", new_versions)
        # print("Default variants:", default_variants)
        # print("Adding recipe with default variants disabled:", default_variants_disable)
        for variant in new_variants:
            # If the variant is not in the default variants, add it,
            # and remove the default variants from the recipe.
            recipe_with_variants = merge_variants(changed_recipe, variant, default_variants)
            for version in new_versions:
                specs.append(recipe_with_variants + "@" + version)

    elif new_variants:
        # Add the recipe with the default variants disabled (that are true) to the specs to check:
        specs.append(f"{changed_recipe[0]}{default_variants_disable}")

        for variant in new_variants:
            # If the variant is not in the default variants, add it,
            # and remove the default variants from the recipe.
            specs.append(merge_variants(changed_recipe, variant, default_variants))

    elif new_versions:
        for version in new_versions:
            specs.append(changed_recipe[0] + "@" + version)
    else:
        print("Adding recipe (found no changed variants or versions):", changed_recipe[0])
        if variants:
            specs.extend([changed_recipe[0] + default_variants_disable, changed_recipe[0]])
        else:
            specs.append(changed_recipe[0])

    new_variants.clear()
    new_versions.clear()
    deprecated.clear()
    changed_recipe[0] = ""


def parse_variant_infos(recipe: str) -> Tuple[ExitCode, dict]:
    """Parse the variants of a recipe and return them as a dictionary."""

    # run spack info --variants-by-name <recipe> to get the variants and their default values
    # Note: Slightly older versions of spack do not have this and there are PRs from them:
    ret, stdout, stderr = run(["bin/spack", "info", "--variants-by-name", recipe])
    if ret:
        print(stderr or stdout)
        return ret, {}
    # The format of the Variants is:
    # Variants:
    #     adios [false]               false, true
    # Extract the variants and their default values from the output:
    variants = {}
    for line in stdout.split("\n"):
        variant = re.search(r"(\w+) \[(\w+)\]", line)
        if variant:
            variants[variant.group(1)] = variant.group(2)

    return Success, variants


def expand_specs_to_check_package_versions(specs_to_check, max_versions) -> List[str]:
    """Expand the specs to check by adding the safe versions of the packages."""
    for spec in specs_to_check.copy():
        recipe = spec.split("@")[0]
        versions = get_safe_versions(recipe)
        if versions:
            specs_to_check.remove(spec)
            specs_to_check.extend([recipe + "@" + version for version in versions[:max_versions]])

    return specs_to_check


def check_all_downloads(specs) -> ExitCode:
    """Check if the sources for installing those specs can be downloaded."""
    fetch_flags = ["--fresh", "--fresh-roots", "--deprecated"]
    for spec in specs:
        info(f"download+sha256 check {specs.index(spec) + 1} of {len(specs)}: {spec}")
        ret = spawn("bin/spack", ["fetch", *fetch_flags, spec])
        if not ret:
            return ret
    return True


def spack_install(specs, args) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Install the packages."""
    passed = []
    failed = []
    for spec in specs:
        if spec.startswith("composable-kernel"):
            print("Skipping composable-kernel: Without a fast GPU, it takes too long.")
            continue

        print(f"\nInstall {spec} ({specs.index(spec) + 1} of {len(specs)}):\n")
        # TODO: Add support for installing the packages in a container, sandbox, or remote host.
        # TODO: Concertize the the spec before installing to record the exact dependencies.

        cmd = ["install", "-v", "--fail-fast", spec]
        cmd += ["^" + dep for dep in args.dependencies.split(",")] if args.dependencies else []

        install_log_filename = f"spack-builder-{spec}.log"

        with LogFile(install_log_filename) as install_log:
            ret = spawn("bin/spack", cmd, logfile=install_log)
            # Check if the installation failed, and if so, print the log file:
            # TODO: Add support for retrying the installation if it fails.
            # If the first line of the log contains "Error: ", clean the misc cache and retry.
            if ret:
                with open(install_log_filename, encoding="utf-8", errors="ignore") as log_file:
                    if "Error: " in log_file.readline():
                        print("Error in the log file, cleaning the misc cache and retrying.")
                        spawn("bin/spack", ["clean", "--misc"])
                        print("Retrying with misc cache cleaned:")
                        ret = spawn("bin/spack", cmd, logfile=install_log)

        if ret == 0:
            print(f"\n------------------------- Passed {spec} -------------------------")
            passed.append(spec)
        else:
            print(f"\n------------------------- FAILED {spec} -------------------------")
            print("\nFailed command:", " ".join(["bin/spack", *cmd]) + "\n")
            print(f"Log file: {install_log_filename}")
            failed.append((spec, install_log_filename))

    return passed, failed


def add_compiler_to_specs(specs_to_check, args) -> List[str]:
    """If indicated, add compilers to use to the specs to check."""

    if not args.compiler:
        return specs_to_check
    if args.compiler != "all":
        compilers = args.compiler.split(",")
    else:
        err, stdout, stderr = run(["bin/spack", "compilers"])
        if err:
            raise ChildProcessError("Failed to get the list of compilers." + (stderr or stdout))
        compilers = []
        for line in stdout.split("\n"):
            if "@" in line:
                print(line)
                compilers.extend(line.split())

    specs_to_check = [spec + " %" + compiler for spec in specs_to_check for compiler in compilers]
    message = " " + " ".join(specs_to_check)
    if len(message) > 70:
        message = message.replace(" ", "\n")
    print("Specs with compilers:", message)
    return specs_to_check


def checkout_pr_by_search_query(args: argparse.Namespace) -> ExitCode:
    """Checkout the PR branch by searching for the PR number."""
    if not args.checkout:
        return Success

    # Find the PR number from the PR query:
    query = f"in:title draft:false -review:changes_requested {args.checkout}"
    find_pr = f"gh pr list --limit 1 -S '{query}' "
    print("Querying for the PR to check out, please wait a second or so:\n" + find_pr)
    exitcode, number = subprocess.getstatusoutput(f"{find_pr} --json number -q.[].number")
    if exitcode != 0 or not number:
        print(f"Failed to find the PR by querying for '{args.checkout}'\n" + number)
        return exitcode or 1

    return checkout_pr_by_number(number)


def checkout_pr_by_number(pr_number: str) -> ExitCode:
    """Checkout the PR branch by PR number."""
    # View the information about the PR:
    spawn("gh", ["pr", "view", pr_number])

    # Checkout the PR branch:
    exitcode, output = subprocess.getstatusoutput(f"gh pr checkout {pr_number}")
    if exitcode != 0:
        print("Failed to checkout the PR branch:", output)
        return exitcode
    print("Checked out the PR branch.")

    # Show the changes in the PR:
    spawn("gh", ["pr", "diff", pr_number])

    # Clean the staging directory (cleaning caches might be nice but causes long delays):
    return spawn("bin/spack", ["clean", "--stage", "--misc"])


def parse_args() -> argparse.Namespace:
    """Run spack install on recipes changed in the current branch from develop."""
    basicConfig(format="%(message)s", level=INFO)

    # Parse the command line arguments using argparse.
    # The arguments are:
    # -l, --label: Label the PR with the results if successful.
    # -d, --download: Download and checksum check only.
    # -s=<versions>, --safe-versions=<versions>: Install <versions> safe versions of the packages.
    # -u, --uninstall: Uninstall the installed packages.
    argparser = argparse.ArgumentParser(description=__doc__)
    argparser.add_argument(
        "-a", "--approve", action="store_true", help="Approve the PR on success."
    )
    argparser.add_argument(
        "-B",
        "--bootstrap",
        action="store_true",
        help="Bootstrap Spack before building the packages.",
    )
    argparser.add_argument(
        "-b",
        "--build",
        help="Build the given list of specs.",
        type=str,
    )
    argparser.add_argument(
        "-c", "--compiler", help="The compiler to use for building the packages."
    )
    argparser.add_argument(
        "-D",
        "--dependencies",
        help="Additional dependency specs for the packages.",
    )
    argparser.add_argument(
        "-k",
        "--checkout",
        help="Checkout the PR branch (find it by PR query) to check the changes.",
        type=str,
    )
    argparser.add_argument(
        "-l", "--label-success", action="store_true", help="Label the PR on success."
    )
    # FIXME: Check of approval from `bin/spack maintainers` is still needed
    # and decline merging if not approved by the maintainers:
    argparser.add_argument("-m", "--merge", action="store_true", help="Merge the PR on success.")
    argparser.add_argument(
        "-s",
        "--safe-versions",
        type=int,
        help="Install <versions> safe versions of the packages.",
    )
    argparser.add_argument(
        "-d", "--download", action="store_true", help="Download and checksum check only"
    )
    argparser.add_argument("-q", "--queue", type=str, help="Work on a queue file of PRs to check.")
    argparser.add_argument(
        "-u", "--uninstall", action="store_true", help="Uninstall the installed packages."
    )
    argparser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output.")
    argparser.add_argument("-y", "--yes", action="store_true", help="Answer yes to all questions.")
    return argparser.parse_args()


def main(args) -> int:
    """Run the main code for the script using the parsed command line flags"""
    # TODO:
    # - Add support for installing the packages in a container, sandbox, or remote host.
    #   Use pxssh module of pexpect: https://pexpect.readthedocs.io/en/stable/api/pxssh.html

    exitcode = authenticate_github_cli()
    if exitcode != Success:
        return exitcode

    if args.bootstrap:
        return bootstrap_spack()

    # Check if the repo has a default remote repository set:
    # It is needed for the gh pr commands to work.
    # If not set, set the default remote repository to the spack repository.:
    default_remote = subprocess.getoutput("gh repo set-default --view")
    if default_remote.startswith("no default repository"):
        print("Setting the default remote repository to spack/spack")
        spawn("gh", ["repo", "set-default", "spack/spack"])

    if args.queue:
        return check_queue_file(args)

    exitcode = checkout_pr_by_search_query(args)
    if exitcode != Success:
        return exitcode

    return check_pr_of_currently_checked_out_branch(args)


def check_pr_of_currently_checked_out_branch(args) -> ExitCode:
    """Check the PR of the currently checked out branch."""

    # Get the number of the current PR:
    # In case we shall approve/merge, we need the PR number so we don't approve/merge the wrong PR.
    exitcode, number = subprocess.getstatusoutput("gh pr view --json number -q .number")
    if exitcode:
        print("Failed to get the PR number:", number)
        return exitcode

    args.pull_request = number
    if not pull_request_is_ready_for_review(args):
        return Success

    return check_and_build(args)


def check_queue_file(args) -> int:
    """Check the queue file of PRs to check."""
    with open(args.queue, "r", encoding="utf-8") as queue:
        args.queue = None
        for line in queue:
            print("Checking PR:", line)
            if line.startswith("#"):
                line = line[1:]
            pr_number = line.split()[0]
            ret = checkout_pr_by_number(pr_number)
            if ret:
                return ret
            args.pull_request = str(pr_number)
            # Check if args.pull_request is already closed or merged:
            pr = get_pull_request_status(args)
            if is_closed_or_merged(pr):
                continue

            exitcode = main(args)
            if exitcode != 0:
                return exitcode
    return Success


def check_and_build(args):
    """Check the PR changes and build the packages."""
    # Get the specs to check.
    if args.build:
        specs_to_check = args.build.split(",")
    else:
        specs_to_check = get_specs_to_check(args)

    print("Specs to check:", " ".join(specs_to_check))

    # Check if the specs have versions and add the versions to the specs to check.

    if args.safe_versions:
        print("Checking for existing safe versions of the packages to build or download")
        # Limit the number of versions to check to 6.
        specs_to_check = expand_specs_to_check_package_versions(specs_to_check, args.safe_versions)

    specs_to_check = add_compiler_to_specs(specs_to_check, args)

    # Check if the sources for installing those specs can be downloaded.
    # This can be skipped as some packages like rust don't have a checksum,
    # and the download is done by the install command anyway.
    if args.download:
        return check_all_downloads(specs_to_check)

    # Check if specs are already installed and ask if they should be uninstalled.
    installed, findings = find_already_installed(specs_to_check)
    if installed:
        print("These specs are already installed:")
        print("\n".join(findings))
        if args.uninstall:
            if args.yes or input("Uninstall them? [y/n]: ").lower() == "y":
                spack_uninstall_packages(installed)
                installed = []

    for already_installed_pkg in installed:
        specs_to_check.remove(already_installed_pkg)

    return build_and_act_on_results(args, installed, specs_to_check)


def head_of_build_log(line: str) -> str:
    """Return the head of the build log."""

    build_log = line.strip()
    if not os.path.exists(build_log):
        return f"Build log not found: {build_log}\n"

    print("Extracting the head of the build log:", build_log)
    with open(build_log, "r", encoding="utf-8") as build_log_file:
        head_of_log = "\n```\nBuild log:\n```py\n"
        for i, log_line in enumerate(build_log_file):
            if i == 2 or "'-G'" in log_line:
                continue  # Skip the long cmake command line for now
            if i > 26:
                head_of_log += "...\n"
                break
            head_of_log += log_line

    return head_of_log


def failure_summary(fails: List[Tuple[str, str]]) -> str:
    """Generate a summary of the failed specs."""
    if not fails:
        return ""

    fails_summary = f"{len(fails)} failed specs:\n" if len(fails) > 1 else "One failed spec:\n"
    for failed_spec, _ in fails:
        fails_summary += f"- `{failed_spec}`\n"

    for failed_spec, log_file in fails:
        fails_summary += f"### `{failed_spec}`:\n```py\n"
        with open(log_file, "r", encoding="utf-8") as log:
            lines = log.readlines()
            previous_line = ""
            add_remaining_lines = False
            next_line_is_build_log = False
            for line in lines:
                if line == "See build log for details:\n":
                    next_line_is_build_log = True
                    continue
                if next_line_is_build_log:
                    fails_summary += head_of_build_log(line)
                    break

                if add_remaining_lines:
                    fails_summary += line
                    continue
                # Match the color code and error marker and look for CMake errors:
                if (
                    r"[0;91m>> " in line
                    or "CMake Error" in line
                    or "errors found in build log" in line
                ):
                    # Include the line before lines with the error marker as well:
                    fails_summary += previous_line
                    fails_summary += line
                    previous_line = ""
                    add_remaining_lines = True
                else:
                    previous_line = line

        fails_summary += "\n```\n"
        if "failed to concretize" in lines[0]:
            fails_summary += "spack failed to concretize specs due to conflicts.\nThis may"
            fails_summary += " be intentional due to a conflict() in the recipe(s):\n"
            fails_summary += "```py\n" + "\n".join(lines) + "\n```\n"

    # TODO: Add support for showing details about the failed specs
    # like used deps (cmake version, openssl version, etc.)
    return fails_summary


def generate_build_results(installed, passed, fails, about_build_host) -> str:
    """Generate a report in markdown format for cut-and-paste into the PR comment."""

    build_results = f"Auto-submitted build results{about_build_host}: (see disclaimer below)\n"
    build_results += "The following specs were checked (extracted from `gh pr diff`):\n"
    build_results += "- `" + "`\n- `".join(installed + passed) + "`\n\n"

    if installed or passed:
        build_results += "The following specs were installed or passed building in this run:"
        build_results += " (variants are shortened, e.g. no disabled variants)\n"
        build_results += "```py\n"
        cmd = ["bin/spack", "find", "--variants", *(installed + passed)]
        build_results += " ".join(cmd)
        build_results += " | sed 's/~[a-z]*//g;s/ [a-z0-9_]*=[a-zA-Z0-9]*//g'\n"
        err, stdout, stderr = run(cmd)
        if not err:
            # Filter out the build system and build type from the output:
            stdout = stdout.replace(" build_system=pip", "")
            stdout = stdout.replace(" build_system=perl", "")
            stdout = stdout.replace(" build_system=cmake", "")
            stdout = stdout.replace(" build_type=Release", "")
            stdout = stdout.replace(" generator=make", "")
            # Remove disabled variants (words following ~) in the stdout:
            stdout = re.sub(r"~[a-z0-9]+", "", stdout)
            build_results += stdout.replace(" build_system=python_pip", "")
        else:
            build_results += stderr or stdout
        build_results += "\n```\n"

    build_results += failure_summary(fails)
    if fails:
        build_results += (
            "\nThis report was generated by a script and may contain errors.\n"
            "The idea would be that I/we can improve this script to get fast checks for PRs!\n"
            "I think this is already much better than just checking checksums manually,"
            "and it should get better as more build error cases get covered properly.\n\n"
            "If the build report contains real errors, please fix them and push the changes.\n\n"
            "The script tries to add a label to indicate the build status,\n"
            "and set the 'draft' status of the PR.\n\n"
            "After the correct fix is pushed, to the PR branch and change the"
            " PR status to 'Ready for review'.\n\n"
            "Generated and submitted by "
        )
    else:
        build_results += "Generated and submitted by "
    git_dir = os.path.dirname(os.path.realpath(__file__))
    err, stdout, stderr = run(["git", "-C", git_dir, "config", "--get", "remote.origin.url"])
    if not err:
        url = stdout.replace("git@github.com:", "https://github.com/").replace(".git", "")
        build_results += url + "/blob/main/"
    build_results += os.path.basename(__file__) + "\n```py\n" + " ".join(sys.argv) + "\n```"

    # Don't show the full path to the files, and replace the home directory with ~:
    build_results = build_results.replace(os.getcwd() + "/", "")
    build_results = build_results.replace(os.path.expanduser("~"), "~")
    return build_results


def check_diff_and_commit(args):
    """Check if the git diff is empty, commit and push the changes if needed."""

    while True:
        log_file = BytesIO()
        spawn("git", ["diff"], logfile=log_file)
        if not log_file.read():
            break

        print("The git diff is not empty, the PR may not be up-to-date.")
        print("Please add the changes to the index and commit them.")
        ret = spawn("git", ["add", "-p"])
        if ret:
            return ret

    spawn("git", ["diff", "--cached"], logfile=log_file)

    if log_file.read():
        err = spawn("git", ["commit"] + (["-m", "Fix the build"] if args.yes else []))
        if err:
            print("Failed to commit the changes.")
            return err
        err = spawn("git", ["push"])
        if err:
            print("Failed to push the changes.")
            return err
    return Success


def build_and_act_on_results(args, installed, specs_to_check):
    """Install the packages and act on the results."""

    passed, failed = spack_install(specs_to_check, args)
    about_build_host, os_name, os_version_id = get_os_info()

    # Generate a report in markdown format for cut-and-paste into the PR comment:
    build_results = generate_build_results(installed, passed, failed, about_build_host)

    # Create a change request for the failed specs:
    if failed and args.approve:
        return create_change_request(args, build_results)

    if args.approve or args.merge:
        ret = check_diff_and_commit(args)
        if ret:
            return ret

    if failed or not passed + installed:
        print(build_results)
        return 1

    if args.label_success:
        label = f"Built on {os_name} {os_version_id}"
        print('All specs passed, labeling the PR with: "{label}"')
        error = spawn("gh", ["pr", "edit", args.pull_request, "--add-label", label])
        if error:
            print("Failed to label the PR.")
            return error

    return check_approval_and_merge(args, build_results)


def get_pull_request_status(args: argparse.Namespace) -> Dict[str, Any]:
    """Get the state of the pull request."""
    if not args.pull_request:
        assert False, "No pull request number given."

    return json.loads(getoutput(f"gh pr view {args.pull_request} --json state,reviews"))


def is_closed_or_merged(pr: Dict[str, Any]) -> bool:
    """Check if the PR is already merged or closed."""

    pr_state = pr.get("state")
    assert pr_state, "Failed to get the PR state."
    return pr_state in ["MERGED", "CLOSED"]


def get_reviews(pr: Dict[str, Any], state: str) -> List[str]:
    """Get the list of approvers of the PR with the given state."""

    approvers = []
    reviews = pr.get("reviews")
    if reviews:
        for review in pr["reviews"]:
            if review["state"] == state:
                approvers.append(review["author"]["login"])

    return approvers


def is_approved_or_changes_requested_by_me(pr: Dict[str, Any]) -> bool:
    """Check if the PR is already approved by me."""

    approvers = get_reviews(pr, "APPROVED")
    if approvers:
        print("Approved  by" + ", ".join(approvers))

    requesters = get_reviews(pr, "CHANGES_REQUESTED")
    if requesters:
        print("Changes requested by:", ", ".join(requesters))

    github_user = get_github_user()
    if not github_user:
        print("Failed to get the GitHub user.")
        raise ConnectionError("Failed to get the GitHub user.")

    return github_user in approvers or github_user in requesters


def pull_request_is_ready_for_review(args: argparse.Namespace) -> bool:
    """Check if the PR is ready for review."""

    pr = get_pull_request_status(args)
    if is_closed_or_merged(pr):
        print("PR is already merged or closed.")
        return False
    if is_approved_or_changes_requested_by_me(pr):
        print("Already approved (or changes requested) by me, skipping approval and merge.")
        if args.yes and args.approve:
            return False
    return True


def create_change_request(args: argparse.Namespace, build_results: str) -> ExitCode:
    """Create a change request for the failed specs."""
    print(build_results)
    if not (args.yes or input("Create a change request for the failed specs [y/n]: ") == "y"):
        return 1

    print("Creating a change request for the failed specs.")
    if not pull_request_is_ready_for_review(args):
        return Success

    # Remove ANSI color codes from the output:
    build_results = re.sub(r"\x1b\[[0-9;]*m", "", build_results)

    # spawn("gh", ["issue", "create", "--title", "Fix the failed specs", "--body", build_results])
    # cmd = ["pr", "review", args.pull_request, "--request-changes", "--body", build_results]
    cmd = ["pr", "review", args.pull_request, "--comment", "--body", build_results]
    exitcode = spawn("gh", cmd)
    if exitcode:
        return exitcode

    error = spawn("gh", ["pr", "edit", args.pull_request, "--add-label", "changes-requested"])
    if error:
        print("Failed to label the PR with changes-requested.")
        return error

    # Set the draft status of the PR to true to prevent merging:
    return spawn("gh", ["pr", "ready", args.pull_request, "--undo"])
    # return Success


def check_approval_and_merge(args: argparse.Namespace, build_results: str):
    """Check if the PR is/can be approved and merge the PR if all specs passed."""

    if args.approve:
        print("Approve requested, please review the PR diff before merging!")
        spawn("gh", ["pr", "diff"])
        # Check if it is already approved:
        # gh pr view 46977 --json reviews,state
        # {
        #   "state": "OPEN"
        #   "reviews": [
        #     {
        #       "author": {
        #         "login": "becker33"
        #       },
        #       "authorAssociation": "MEMBER",
        #       "body": "",
        #       "submittedAt": "2024-10-14T23:15:56Z",
        #       "includesCreatedEdit": false,
        #       "reactionGroups": [],
        #       "state": "APPROVED"
        #     }
        #   ],

        # }
        # cmd = ["gh", "pr", "view", args.pull_request, "--json", "state", "-q", ".state"]

        if not pull_request_is_ready_for_review(args):
            return Success

        print("\nBuild results:\n\n")
        print(build_results + "\n\n")

        if (
            args.yes
            or not get_reviews(get_pull_request_status(args), "APPROVED")
            or input("Submit the build results as an approval [y/n]: ") == "y"
        ):
            # Check if the PR is really ready for approval before approving:
            # Ask for confirmation before approving the PR.
            if args.yes or input("Do you really want to approve this PR now? [y/n]: ") == "y":
                cmd = ["pr", "review", args.pull_request, "--approve", "--body", build_results]
                exitcode = spawn("gh", cmd)
                if exitcode:
                    return exitcode
            else:
                print("Skipping approval of the PR")
    else:
        print(build_results)

    return merge_pr_if_requested(args)


def merge_pr_if_requested(args) -> ExitCode:
    """Merge the PR if all specs passed."""
    # Merge the PR if all specs passed. Only pass -m/--merge if you really want to merge.
    # TODO: Check if approved by needed reviewers, etc.

    # TODO: Add support for checking if the PR is ready for merge before merging.
    # Especially check if questions are answered and the merge does not need
    # to wait for checks or reviews. This can be done with the GitHub API/CLI.
    # Review wait status can be checked using labels, comments, etc.

    if args.merge:
        if not args.approve:
            print("Merge requested, please review the PR diff before merging!")
            spawn("gh", ["pr", "diff"])
        if args.yes or input("\n\nMERGE this PR now? [y/n]: ") == "y":
            # TODO: Check/Fix the PR title and squashed commit messages for the correct format.
            print("Merging the PR:")
            cmd = ["pr", "merge", args.pull_request, "--squash", "--auto"]
            return spawn("gh", cmd)

    return Success


def parse_args_and_run():
    """Parse the command line arguments and run the main function."""

    # Add ~/.local/bin to the PATH if it is not already there.
    if "/.local/bin" not in os.environ.get("PATH", ""):
        os.environ["PATH"] = os.path.expanduser("~/.local/bin:" + os.environ.get("PATH", ""))

    ret = main(parse_args())
    if ret:
        sys.exit(ret)


if __name__ == "__main__":
    parse_args_and_run()

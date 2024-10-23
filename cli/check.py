#!/usr/bin/env python3
"""Tool to run 'spack install' on changed recipes by a checked out PR branch."""
# Copyright 2024, Bernhard Kaindl
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

# TODOs:
# - run spack maintainers to check for maintainers of the packages.
#   Only attempt to merge if the maintainers approved merging the PR.
# - Limit the amount of builds: For some PR, the amount of versions*variants can be >300.
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
from glob import glob
from io import BytesIO
from logging import INFO, basicConfig, info
from pathlib import Path
from shutil import which
from subprocess import getoutput
from typing import Any, Dict, List, Tuple, TypeAlias

from _vendor import pexpect

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


def update_terminal_status_bar(message: str, args: List[str]) -> None:
    """Update the terminal's terminal status bar with the basename of the current directory"""

    message = " ".join([message, *args])[:50]
    cwd = os.getcwd()
    if cwd.startswith(os.path.expanduser("~")):
        cwd = cwd.replace(os.path.expanduser("~"), "~")
    else:
        cwd = cwd.split("/")[-1]
    status = f"{cwd}: {message}"
    print(f"\033]0;{status}\007", end="")


def spawn(command: str, args, logfile=None, **kwargs) -> ExitCode:
    """Spawn a command with input and output passed through, with a pyt and exit code."""

    update_terminal_status_bar(command, args)
    if kwargs.get("show_command", True):
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
        data = re.sub(b":+", b":", data).replace(b"           :", b"")
        data = data.replace(b"\n *:\n", b"\n").replace(b"\n+", b"\n")
        if "filter_output" in kwargs:
            data = kwargs["filter_output"](data)
        # remove the current working directory and empty lines from the output:
        return data.replace(cwd, b"")

    child.interact(
        # The type annotation is wrong in pexpect, it should be str | None, not str:
        escape_character=None,  # type:ignore # pyright: ignore[reportArgumentType]
        # The type annotation is wrong in pexpect, it should be func(bytes) -> bytes:
        # input_filter=filter_suspended_output,  # type:ignore
        output_filter=filter_output,  # type:ignore
    )

    child.expect(pexpect.EOF)
    child.close()
    update_terminal_status_bar(f"{child.exitstatus}: {command}", args)
    return int(child.exitstatus or 0)


def update_apt_package_cache() -> ExitCode:
    """Update the apt package cache"""

    # Install the needed packages on Debian/Ubuntu.
    # If /var/cache/apt/pkgcache.bin older than 24 hours, update the package list.
    if os.path.exists("/var/cache/apt/pkgcache.bin"):
        if os.path.getmtime("/var/cache/apt/pkgcache.bin") < time.time() - 86400:
            error = spawn("sudo", ["apt-get", "update"])
            if error:
                print("Failed to update the package list.")
                return error
    return Success


def install_github_cli_debian_repo() -> ExitCode:
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

    return Success


def install_spack_dependencies_on_debian() -> ExitCode:
    """Install the dependencies of Spack."""

    # Set the environment variables to avoid some interactive prompts
    os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    os.environ["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
    os.environ["APT_LISTCHANGES_FRONTEND"] = "none"
    os.environ["APT_LISTBUGS_FRONTEND"] = "none"
    os.environ["NEEDRESTART_SUSPEND"] = "y"
    os.environ["NEEDRESTART_MODE"] = "l"

    if install_github_cli_debian_repo() or update_apt_package_cache():
        return 1

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
        "gh",  # GitHub CLI
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
        err, output = subprocess.getstatusoutput(tool + " --version")
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


def gh_set_alias(name: str, cmd: str) -> None:
    """Set a GitHub CLI alias."""
    ret = spawn("gh", ["alias", "set", "--clobber", name, "--shell", cmd], show_command=False)
    if ret:
        raise ChildProcessError(f"Failed to set the alias {name} to the command {cmd}.")


def gh_set_checkout_alias(name: str, github_pull_request_search_expressions: List[str]) -> None:
    """Set a GitHub CLI alias for checking out PRs."""

    query_string = " ".join(github_pull_request_search_expressions)
    github_pull_request_list_args = f"-S '{query_string}'"
    fzf_pr_list = f'id="$(gh pr list -L60 {github_pull_request_list_args}|fzf|cut -f1)"'
    checkout_id = """;[ -n "$id" ] && gh pr checkout $id && gh pr view -c && gh pr diff"""
    gh_set_alias(name, fzf_pr_list + checkout_id)


def setup_github_cli_fzf_aliases() -> ExitCode:
    """Set up the fzf fuzzy finder for the shell and the GitHub CLI commands/aliases."""

    exitcode, _, __ = run(["which", "fzf"])
    if exitcode:
        print("fzf is not installed, please install it.")
        return exitcode

    # Set up the GitHub CLI aliases for checking out PRs:
    updated_recently = "updated:>2024-06-01"
    # Add an alias "gh co" to checkout any recent (last 60) PR:
    gh_set_checkout_alias("co", [updated_recently])
    query_review_needed = [
        "review:required",
        "draft:false",
        "no:assignee",
        "-status:failure",
        "-label:changes-requested",
        "-label:waiting-on-maintainer",
        "-label:waiting-on-dependency",
        updated_recently,
    ]
    gh_set_checkout_alias("co-review-needed", query_review_needed)
    gh_set_checkout_alias("co-review-title-add", query_review_needed + ["in:title add"])
    gh_set_checkout_alias("co-review-title-new", query_review_needed + ["in:title new"])
    return Success


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

    # For cuda, we'd have to add cuda_arch that is supported by the recipe,
    # so we can't just add all cuda_arch variants as we don't autodetect supported cuda_arch:
    if not variant or variant.group(1) == "cuda":
        return

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
            version_match = None

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


def add_recipe_variant_version(
    specs: List[str],
    changed_recipe: List[str],
    new_variants: List[str],
    new_versions: List[str],
    deprecated: List[str],
):
    """Add the recipe, variants, and versions to the specs to check."""
    if not changed_recipe[0]:
        return

    variants: Dict[str, str] = {}
    if new_variants:
        ret, variants = parse_variant_infos(changed_recipe[0])
        if ret:
            print("Error getting variants of", changed_recipe[0])

    # Add the recipe with the default variants disabled (that are true) to the specs to check:
    # If the recipe has no variants, add the recipe without variants.
    # Get the list of variants that are true by default:
    default_variants = [variant for variant, value in variants.items() if value == "true"]
    if "cuda" in variants:
        # vtk-m enables +cuda even though it is not in the default variants.
        default_variants.append("cuda")

    # Prepend ~ to all default variants to disable them.
    default_variants_disable = "".join(["~" + variant for variant in default_variants])

    # Don't disable some default variants that are commonly used(paraview~opengl2 fails to build):

    # Remove ~adios2, ~mpi, ~shared, ~static, ~python from default_variants_disable:
    skip_disable = ["adios2", "mpi", "opengl2", "shared", "static", "python"]
    for skip in skip_disable:
        if skip in default_variants:
            default_variants.remove(skip)
            default_variants_disable = default_variants_disable.replace("~" + skip, "")

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

    # Some custom massaging for the conflicting variants in paraview (hope this works)
    for spec in specs:
        if "+fides" in spec and "+adios2" not in spec:
            print("found fides without adios2")
            specs.remove(spec)
            specs.append(spec.replace("~adios2", "") + "+adios2")

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


def filter_spec_data(specs: str) -> str:
    """Filter extra verbose data from the spec output."""

    # Filter out the build system and build type from the output:
    specs = re.sub(r" build_system=[a-z]+", "", specs)
    specs = re.sub(r" build_type=[a-zA-Z]+", "", specs)
    specs = re.sub(r" generator=[a-zA-Z]+", "", specs)
    specs = re.sub(r" arch=[a-z0-9.-]+", "", specs)
    # Remove disabled variants (words following ~) in the stdout:
    # specs = re.sub(r"~[a-z0-9]+", "", specs)
    specs = specs.replace(r"%gcc@13.1.0", "")
    return specs


def spack_install(specs, args) -> Tuple[List[str], List[Tuple[str, str]], List[str], List[str]]:
    """Install the packages."""
    passed = []
    failed = []
    already_requested: List[str] = []
    requested_changes_for: List[str] = []
    for spec in specs:
        if spec.startswith("composable-kernel"):
            print("Skipping composable-kernel: Without a fast GPU, it takes too long.")
            continue

        print(f"\nInstall {spec} ({specs.index(spec) + 1} of {len(specs)}):\n")

        cmd = ["install", "-v", "--fail-fast"]
        if args.build and "@" in args.build:
            cmd += ["--deprecated"]  # If --build was used, the version might be deprecated.

        cmd += [spec]
        cmd += ["^" + dep for dep in args.dependencies.split(",")] if args.dependencies else []

        install_log = f"spack-builder-{spec}.log"

        with LogFile(install_log) as install_logfile:
            ret = spawn("bin/spack", cmd, logfile=install_logfile)

        if ret:  # If the installation failed, clean the misc cache and retry
            with open(install_log, encoding="utf-8", errors="ignore") as log_file:
                # If the first line of the log contains "Error: ", clean the misc cache and retry.
                if "Error: " in log_file.readline():
                    print("Error in the log file, cleaning the misc cache and retrying.")
                    spawn("bin/spack", ["clean", "--misc"])
                    print("Retrying with misc cache cleaned:")
                    ret = spawn("bin/spack", cmd, logfile=install_logfile)

        if ret == 0:
            print(f"\n------------------------- Passed {spec} -------------------------")
            passed.append(spec)
        else:
            print(f"\n------------------------- FAILED {spec} -------------------------")
            command = " ".join(["bin/spack", *cmd])
            print("\nFailed command:\n\n", command + "\n")
            print(f"Log file: {install_log}")
            failed.append((spec, install_log))

            if args.request_changes:
                print(f"\n------------------------- FAILED {spec} -------------------------")
                header = "This command failed: `" + command + "`\n"
                raw_report = header + failure_summary([(spec, install_log)])
                print(raw_report)
                print(f"------------------------- FAILED {spec} -------------------------")
                pr = get_pull_request_status(args)
                for review in pr.get("reviews", []):
                    if review.get("state") != "CHANGES_REQUESTED":
                        continue
                    if command in review.get("body", ""):
                        print("Already requested changes for", spec)
                        already_requested.append(spec)

                if spec not in already_requested:
                    input_str = f"Request changes for {spec} in {args.pull_request_url}:? [y/N] "
                    if not args.yes and input(input_str).lower() != "y":
                        continue

                    raw_report += abbreviated_spec_info(spec, install_log + ".spec")
                    report = remove_color_terminal_codes(raw_report)

                    print("Writing report to", install_log + ".report")
                    with open(install_log + ".report", "w", encoding="utf-8") as report_file:
                        report_file.write(report)

                    kind = "--comment"
                    if args.request_changes:
                        print("Request changes? (else the report is added just comment):")
                        req = input_str = f"Request changes to {args.pull_request_url}:? [y/N] "
                        if req == "y":
                            kind = "--request-changes"
                    else:
                        req = input_str = f"Add a comment to {args.pull_request_url}:? [y/N] "
                        if req != "y":
                            continue

                    ret = spawn("gh", ["pr", "review", kind, "--body", report], show_command=False)
                    if ret:
                        print("Failed to request changes for", spec)
                        raise ChildProcessError("Failed to request changes for " + spec)
                    requested_changes_for.append(spec)

    if args.verbose:
        print("Summary:")
        print("Passed:", " ".join(passed))
        print("Failed:", " ".join([fail[0] for fail in failed]))
        print("Requested changes for:", " ".join(requested_changes_for))
        print("Already requested changes for:", " ".join(already_requested))
    return passed, failed, requested_changes_for, already_requested


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
    query = f"in:title {args.checkout}"
    find_pr = f"gh pr list --limit 1 --search '{query}' "
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

    # Clean the staging directory:
    # The repository cache could be cleaned as well, but it causes long delays
    # and errors from stale repository cache should now be handled by detecting the error.
    # running spack clean --misc and retrying the installation now. Thus, hopefully
    # is not longer needed to clean the misc cache on each PR checkout:
    return spawn("bin/spack", ["clean", "--stage"])


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
        "-f", "--force", action="store_true", help="Force the approval of packages."
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
        "-r", "--request-changes", action="store_true", help="Request changes on failure."
    )
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

    remote = subprocess.getoutput("git ls-remote --get-url")
    if "/spack" not in remote:
        print("gh-spack-pr: The remote of the current branch does not appear to be a spack repo:")
        print("'git ls-remote --get-url' shows:", remote)
        print("Please see -h | --help for help on gh-spack-pr usage.")
        return 1

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

    # Get URL of the current PR for displaying in the logs:
    args.pull_request_url = subprocess.getoutput("gh pr view --json url -q .url")

    # Get the number of the current PR:
    # We use it for any further API calls so we don't act on the wrong PR.
    args.pull_request = args.pull_request_url.split("/")[-1]

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


def head_of_build_log(failed_spec: str, line: str) -> str:
    """Return the head of the build log."""

    build_log = line.strip()
    if not os.path.exists(build_log):
        return f"Build log not found: {build_log}\n"

    skip = [
        "Compatibility with CMake",
        "CMake Deprecation Warning",
        "OLD behavior",
        "  CMake.",
        "  of CMake.",
        "Update the VERSION argument",
        "compatibility with older versions.",
        "compiler: lib/spack/env",
        "Detecting C compiler",
    ]
    with open(build_log, "r", encoding="utf-8") as build_log_file:
        log = f"<details><summary>Head of the raw log for {failed_spec}</summary>\n\n```py\n"
        for i, log_line in enumerate(build_log_file):
            if i <= 2 or "'-G'" in log_line:
                continue  # Skip the long cmake command line for now
            if i > 42:
                log += "...\n"
                break
            if not log_line or log_line.isspace():
                continue
            for skip_line in skip:
                if skip_line in log_line:
                    continue
            if log_line.startswith("    '"):
                log_line = log_line.replace("'", "")
            log += log_line
    log += "\n```\n</details>\n\n"
    return log


def remove_long_strings(data: str) -> str:
    """Remove long strings in the output."""

    cwd = f"{os.getcwd()}/"
    # remove '-DCMAKE_.*:STRING=<any text>' from the output:
    data = re.sub(" '-DCMAKE_.*:STRING=.*'", "", data)
    # remove extra consecutive :: from the output:
    data = re.sub(":+", ":", data).replace("           :", "")
    # remove the current working directory and empty lines from the output:
    return data.replace(cwd, "$PWD/").replace("\n:\n", "\n").replace("\n\n", "\n")


def remove_color_terminal_codes(data: str) -> str:
    """Remove color terminal codes from the output."""
    return re.sub(r"\x1b\[[0-9;]*m", "", data)


def abbreviated_spec_info(spec: str, spec_log_file: str) -> str:
    """Return the abbreviated spec info."""

    print(f"Getting `spack spec {spec}` ...")
    with LogFile(spec_log_file + ".spec") as spec_log:
        # os.environ["TERM"] = "dumb"
        ret = spawn("bin/spack", ["spec", spec], logfile=spec_log, output_filter=filter_spec_data)
        if ret:
            raise ChildProcessError("Failed to get the spec for " + spec)
    with open(spec_log_file + ".spec", encoding="utf-8", errors="ignore") as spec_log:
        spec_report = filter_spec_data(spec_log.read())

    report = f"\n\n<details><summary>Expand the spec output `spack spec {spec}`</summary>"
    return report + "\n\n```yaml\n" + spec_report + "\n```\n\n</details>\n\n"


def failure_summary(fails: List[Tuple[str, str]], **kwargs) -> str:
    """Generate a summary of the failed specs."""
    if not fails:
        return ""

    fails_summary = f"{len(fails)} failed specs:\n" if len(fails) > 1 else ""
    if len(fails) > 2:
        for failed_spec, _ in fails:
            fails_summary += f"- `{failed_spec}`\n"

    for failed_spec, log_file in fails:
        fails_summary += f"<details><summary>Failed spec: {failed_spec}</summary>\n\n"
        fails_summary += f"### `{failed_spec}`:\n"
        errors = ""
        with open(log_file, "r", encoding="utf-8") as log:
            lines = log.readlines()
            previous_line = ""
            add_remaining_lines = 0
            next_line_is_build_log = False
            for line in lines:
                if line == "See build log for details:\n":
                    next_line_is_build_log = True
                    continue
                if next_line_is_build_log:
                    fails_summary += head_of_build_log(failed_spec, line)
                    break

                if add_remaining_lines:
                    line = re.sub("'-DCMAKE_.*:STRING=.*'", "", line)
                    if line.startswith("    '"):
                        line = line.replace("'", "")
                    errors += line
                    add_remaining_lines -= 1
                    continue

                # Match the color code and error marker and look for CMake errors:
                error_markers = [
                    r"[0;91m",
                    "Error:",
                    "error:",
                    "FAILED",
                    "failed",
                ]
                for marker in error_markers:
                    if marker in line:
                        errors += previous_line
                        errors += line
                        previous_line = ""
                        add_remaining_lines = 2
                        break
                else:
                    previous_line = line
            if errors:
                fails_summary += f"```py\n{errors}```\n"
            fails_summary += "\n</details>\n\n"

        # When include_specs in kwargs, include the specs in the summary:
        if "include_specs" in kwargs:
            fails_summary += abbreviated_spec_info(failed_spec, log_file + ".spec")

        if "failed to concretize" in lines[0]:
            fails_summary += "spack failed to concretize specs due to conflicts.\nThis may"
            fails_summary += " be intentional due to a conflict() in the recipe(s):\n"
            fails_summary += "```py\n" + "\n".join(lines) + "\n```\n"

    # TODO: Add support for showing details about the failed specs
    # like used deps (cmake version, openssl version, etc.)
    return fails_summary


def remove_too_verbose_output(abstract_spec_str: str) -> str:
    """Remove too verbose output from the abstract spec."""

    # Filter out the build system and build type from the output:
    abstract_spec_str = abstract_spec_str.replace(" build_system=pip", "")
    abstract_spec_str = abstract_spec_str.replace(" build_system=perl", "")
    abstract_spec_str = abstract_spec_str.replace(" build_system=autotools", "")
    abstract_spec_str = abstract_spec_str.replace(" build_type=Release", "")
    abstract_spec_str = abstract_spec_str.replace(" generator=make", "")
    # Remove disabled variants (words following ~) in the stdout:
    return re.sub(r"~[a-z0-9]+", "", abstract_spec_str)


def spack_find_summary(spack_find_output: str) -> str:
    """Convert the spack find output to an HTML-like summary that can be expanded."""

    details = " (disabled variants are removed for the make the list the dependencies brief)"
    head = "<details><summary>"
    head += "Click on this line to unfold and refold the dependencies of this build\n\n\n```py\n"
    html = ""
    for line in spack_find_output.split("\n"):
        cooked = remove_too_verbose_output(line)
        if not cooked:
            continue
        if line[:3] == "-- ":
            # remove " -<any number of dashes>" from the end of the line:
            html += "### Using " + re.sub(r" -+.*$", "", line[3:]) + ":\n"
            continue
        if line[0] != " ":  # This is a build, add a summary for it
            if not html or not html.endswith(":\n"):
                html += "```\n</details>"
            html += f"{head}{cooked}\n```\n</summary>\n\nDependency tree{details}:\n```py\n"
            html += line + "\n"
        else:
            html += cooked + "\n"
        if len(html) > 8000:
            html += "... (truncated)"
            break
    return html + "```\n</details>\n\n"


def generate_build_results(installed, passed, fails, about_build_host) -> str:
    """Generate a report in markdown format for cut-and-paste into the PR comment."""

    build_results = f"Build results{about_build_host}: "
    build_results += "These changed specs were found `gh pr diff`:\n"
    build_results += "- `" + "`\n- `".join(installed + passed) + "`\n\n"

    if installed or passed:
        build_results += "The following specs were built (or installed) to check this PR:\n"
        # build_results += "```py\n"
        cmd = ["bin/spack", "find", "--deps", "--variants", *(installed + passed)]
        # build_results += " ".join(cmd) + "\n```\n"
        # build_results += " | sed 's/~[a-z]*//g;s/ [a-z0-9_]*=[a-zA-Z0-9]*//g'\n```\n"
        err, stdout, stderr = run(cmd)
        if err:
            build_results += stderr or stdout
        else:
            build_results += spack_find_summary(stdout)

    build_results += failure_summary(fails)
    if fails:
        build_results += (
            "\nThis report was generated by a script that is a work-in-progress.\n"
            "If this found a real issue, please fix it and push the changes.\n\n"
        )
    build_results += "Generated by "
    git_dir = os.path.dirname(os.path.realpath(__file__))
    err, stdout, stderr = run(["git", "-C", git_dir, "config", "--get", "remote.origin.url"])
    if not err:
        url = stdout.replace("git@github.com:", "https://github.com/").replace(".git", "")
        build_results += url + f"/blob/main/{os.path.basename(__file__)} "
        build_results += " ".join(sys.argv[1:]) + "\n"

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

    passed, failed, requested_changes_for, already_requested = spack_install(specs_to_check, args)
    about_build_host, os_name, os_version_id = get_os_info()

    # Remove the already requested changes from the failed specs:
    report_failed = [spec for spec in failed if spec[0] not in already_requested]
    # Remove the requested changes from the failed specs:
    report_failed = [spec for spec in report_failed if spec[0] not in requested_changes_for]

    # Generate a report in markdown format for cut-and-paste into the PR comment:
    build_results = generate_build_results(installed, passed, report_failed, about_build_host)

    # Create a change request for the failed specs:
    if report_failed and args.request_changes:
        return create_change_request(args, build_results)

    if args.approve or args.merge:
        ret = check_diff_and_commit(args)
        if ret:
            return ret

    if failed or not passed + installed:
        print("Link to the PR:", args.pull_request_url)
        return 1

    if args.label_success:
        # Not actively used now, but could be used to label the PR with the build status:
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

    return json.loads(getoutput(f"gh pr view {args.pull_request} --json state,reviews,labels"))


def is_closed_or_merged(pr: Dict[str, Any]) -> bool:
    """Check if the PR is already merged or closed."""

    pr_state = pr.get("state")
    assert pr_state, "Failed to get the PR state."
    return pr_state in ["MERGED", "CLOSED"]


def get_reviewers(pr: Dict[str, Any], state: str) -> List[str]:
    """Get the list of approvers of the PR with the given state."""

    approvers = []
    for review in pr.get("reviews", []):
        if review["state"] == state:
            approvers.append(review["author"]["login"])

    return approvers


def get_labels(pr: Dict[str, Any]) -> List[str]:
    """Get the list of labels of the PR."""

    labels = []
    for label_entry in pr.get("labels", []):
        labels.append(label_entry["name"])

    return labels


def changes_requested(args: argparse.Namespace, pr: Dict[str, Any]) -> bool:
    """Check if no changes are requested on the PR."""

    if args.force:
        return False
    return get_reviewers(pr, "CHANGES_REQUESTED") != [] or "changes-requested" in get_labels(pr)


def print_reviewers(pr: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Print the reviewers of the PR."""

    approvers = get_reviewers(pr, "APPROVED")
    if approvers:
        print("Approved by " + ", ".join(approvers))

    requesters = get_reviewers(pr, "CHANGES_REQUESTED")
    if requesters:
        print("Changes requested by:", ", ".join(requesters))

    return approvers, requesters


def is_approved_or_changes_requested_by_me(pr: Dict[str, Any]) -> bool:
    """Check if the PR is already approved by me."""

    approvers, requesters = print_reviewers(pr)
    github_user = get_github_user()
    if not github_user:
        print("Failed to get the GitHub user.")
        raise ConnectionError("Failed to get the GitHub user.")

    return github_user in approvers or github_user in requesters


def pull_request_is_ready_for_review(args: argparse.Namespace) -> bool:
    """Check if the PR is ready for review."""

    print("Checking the approval status of the PR:", args.pull_request_url)
    pr = get_pull_request_status(args)
    if is_closed_or_merged(pr):
        print("PR is already merged or closed.")
        return False
    if is_approved_or_changes_requested_by_me(pr):
        print(f"{args.pull_request_url} is already approved (or changes requested) by me.")
        if args.force:
            print("Force flag is set, will build, approve, and merge the PR.")
        elif args.approve or args.merge:
            print("Skipping approval and/or merge.")
        if args.yes and args.approve and not args.force:
            return False
    return True


def create_change_request(args: argparse.Namespace, build_results: str) -> ExitCode:
    """Create a change request for the failed specs."""
    print(build_results)

    if not pull_request_is_ready_for_review(args):
        print("The PR is not ready for review, skipping creating a change request.")
        return Success

    if not (args.yes or input("Create a change request for the failed specs [y/n]: ") == "y"):
        return 1
    print("Creating a change request for the failed specs.")

    if args.yes:
        build_results += (
            "The script automatically adds a label for tracking to indicate the build status,\n"
            "and sets the 'draft' status of the PR.\n\n"
            "If there is no (longer) an issue, please change the PR to 'Ready for review' again."
        )

    build_results = remove_color_terminal_codes(build_results)

    # spawn("gh", ["issue", "create", "--title", "Fix the failed specs", "--body", build_results])
    # cmd = ["pr", "review", args.pull_request, "--request-changes", "--body", build_results]
    cmd = ["pr", "review", args.pull_request, "--comment", "--body", build_results]
    exitcode = spawn("gh", cmd, show_command=False)
    if exitcode:
        return exitcode

    error = spawn("gh", ["pr", "edit", args.pull_request, "--add-label", "changes-requested"])
    if error:
        print("Failed to label the PR with changes-requested.")
        return error

    # Set the draft status of the PR to true to prevent merging:
    return spawn("gh", ["pr", "ready", args.pull_request, "--undo"])
    # return Success


def review_pr(args: argparse.Namespace, kind: str, build_results: str) -> ExitCode:
    """Submit a review to the PR with the build results."""

    cmd = ["pr", "review", args.pull_request, kind, "--body", build_results]
    return spawn("gh", cmd, show_command=False)


def check_approval_and_merge(args: argparse.Namespace, build_results: str):
    """Check if the PR is/can be approved and merge the PR if all specs passed."""

    if args.approve:
        print("Approve requested, please review the PR diff before merging!")
        spawn("gh", ["pr", "diff"])

        if not pull_request_is_ready_for_review(args):
            return Success

        print("\nBuild results:\n\n")
        print(build_results + "\n\n")
        print("Link to the PR:", args.pull_request_url)

        pr = get_pull_request_status(args)
        if changes_requested(args, pr):
            print("Changes requested by reviewers, skipping approval of the PR.")
            # Ask if the build results should be added as a comment to the PR:
            if args.yes or input("Add the build results as a comment to the PR [y/n]: ") == "y":
                review_pr(args, "--comment", build_results)

            return Success

        print_reviewers(pr)

        # Check if the PR is really ready for approval before approving:
        # Ask for confirmation before approving the PR.
        target = "approval" if not changes_requested(args, pr) else "comment"
        if args.yes or input(f"Submit the build results as an {target} [y/n]: ") == "y":
            option = "--approve" if not changes_requested(args, pr) else "--comment"
            exitcode = review_pr(args, option, build_results)
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

        pr = get_pull_request_status(args)
        if changes_requested(args, pr):
            print("Changes requested by reviewers, skipping approval of the PR.")
            return Success

        # Show the current status of the PR:
        spawn("gh", ["pr", "view", args.pull_request])

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

#!/usr/bin/env python3
"""For reviewing pull requests, run `spack install` on recipes changed current PR"""
# Copyright 2024, Bernhard Kaindl
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
import argparse
import os
import re
import signal
import subprocess
import sys
import time
import traceback
from io import BytesIO
from glob import glob
from logging import INFO, basicConfig, info
from pathlib import Path
from shutil import which
from time import sleep
from typing import List, Tuple, TypeAlias

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

    cwd = os.getcwd().encode()

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
        error = spawn("sudo", ["apt-get", "install", "-y", *tools])
        if error:
            print("Failed to install the optional tooling packages.")
            return error

    # Use pipx to install the latest versions of pre-commit and black:
    for tool in ["pre-commit", "black"]:
        if not which(tool):
            error = spawn("pipx", ["install", tool])
            if error:
                print(f"Failed to install the latest version of {tool}.")
                return error

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


def authenticate_github_cli() -> ExitCode:
    """Authenticate with GitHub, paste the URL in a browser, and paste the one-time code."""
    if not which("gh"):  # Don't block use in containers without GitHub CLI using -b <spec>
        return Success

    # Check if the user is already authenticated with GitHub.
    exitcode, out, err = run(["gh", "auth", "status"])
    if not exitcode:
        return Success

    print(err or out)

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

    return setup_github_cli_dashboard(build_tools_dir)


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
        command, check=check, text=True, capture_output=True, timeout=120
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


# Of course, this diff parser is not perfect, and should be a class, but it's a start.
def get_specs_to_check(args) -> List[str]:
    """Check if the current branch is up-to-date with the remote branch.

    Check if the current branch is up-to-date with the remote branch.
    On errors and if not up-to-date, return an error exit code.
    """
    changed_files: List[str] = []
    changed_recipe: List[str] = [""]
    recipes: List[str] = []
    specs: List[str] = []
    new_variants: List[str] = []
    new_versions: List[str] = []
    next_line_is_version = False
    next_line_is_variant = False

    # The most reliable way to get the PR diff is to use the GitHub CLI:
    err, stdout, stderr = run(["gh", "pr", "diff"])
    if err or stderr:
        print(stderr or stdout)
        sys.exit(err)

    for line in stdout.split("\n"):
        if line.startswith("diff --git"):
            add_recipe_variant_version(specs, changed_recipe, new_variants, new_versions)
            next_line_is_version = False
            next_line_is_variant = False
            continue
        if line[0] != "+":
            continue

        check_for_recipe(line, changed_files, changed_recipe, recipes)
        if not changed_recipe[0]:
            continue

        # A version with indent by 8 spaces is a version that is likely deprecated:
        if re.search(r"        version\(", line):
            continue

        # Get the list of new and changed versions from the PR diff:
        version_start = re.search(r"    version\($", line)  # version(
        if version_start:
            next_line_is_version = True
            continue
        version = re.search(r'    version\("([^"]+)", ', line)  # version("version",
        if next_line_is_version or version:
            next_line_is_version = False
            version = version or re.search(r'"([^"]+)"', line)
            if version:
                new_versions.append(version.group(1))
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
            next_line_is_variant = False
            variant = variant or re.search(r'"([^"]+)"', line)
            if variant:
                new_variants.append(variant.group(1))
            continue

    add_recipe_variant_version(specs, changed_recipe, new_variants, new_versions)

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


def add_recipe_variant_version(specs, changed_recipe, new_variants, new_versions):
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
    changed_recipe[0] = ""


def parse_variant_infos(recipe: str) -> Tuple[ExitCode, dict]:
    """Parse the variants of a recipe and return them as a dictionary."""

    # run spack info --variants-by-name <recipe> to get the variants and their default values
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
        if ret == 0:
            print(f"\n------------------------- Passed {spec} -------------------------")
            passed.append(spec)
        else:
            print(f"\n------------------------- FAILED {spec} -------------------------")
            print("\nFailed command:", " ".join(["bin/spack", *cmd]) + "\n")
            print(f"Log file: {install_log_filename}")
            # show the last 40 lines of the log file:
            spawn("tail", ["-n", "40", install_log_filename])
            sleep(5)
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

    # View the information about the PR:
    exitcode, output = subprocess.getstatusoutput(f"gh pr view {number}")
    if exitcode != 0:
        print("Failed to view the PR:", output)
        return exitcode
    print(f'Found PR for "{args.checkout}":')
    print(output)
    # Checkout the PR branch:
    exitcode, output = subprocess.getstatusoutput(f"gh pr checkout {number}")
    if exitcode != 0:
        print("Failed to checkout the PR branch:", output)
        return exitcode
    print("Checked out the PR branch.")

    # Clean the python and misc cache files:
    exitcode, output = subprocess.getstatusoutput("bin/spack clean --misc-cache --python-cache")
    if exitcode != 0:
        print("Failed to clean the cache:", output)
        return exitcode
    print("Cleaned the python and the misc caches")
    return Success


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

    exitcode = checkout_pr_by_search_query(args)
    if exitcode != Success:
        return exitcode

    # Get the number of the current PR:
    # In case we shall approve/merge, we need the PR number so we don't approve/merge the wrong PR.
    exitcode, output = subprocess.getstatusoutput("gh pr view --json number -q .number")
    if exitcode != 0:
        print("Note: ", output)

    args.pull_request = output

    if args.bootstrap:
        return bootstrap_spack()

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
            if input("Uninstall them? [y/n]: ").lower() == "y":
                spack_uninstall_packages(installed)
                installed = []

    for already_installed_pkg in installed:
        specs_to_check.remove(already_installed_pkg)

    return build_and_act_on_results(args, installed, specs_to_check)


def failure_summary(fails: List[Tuple[str, str]]) -> str:
    """Generate a summary of the failed specs."""
    if not fails:
        return ""

    fails_summary = f"{len(fails)} failed specs:" if len(fails) > 1 else "One failed spec:"
    for failed_spec, _ in fails:
        fails_summary += f"- `{failed_spec}`\n"

    for failed_spec, log_file in fails:
        fails_summary += f"### `{failed_spec}`:\n```py\n"
        with open(log_file, "r", encoding="utf-8") as log:
            lines = log.readlines()
            # Print one line before lines with the error marker as well:
            previous_line = ""
            for line in lines:
                if r"[0;91m>> " in line:  # Match the color code and error marker.
                    fails_summary += previous_line
                    fails_summary += line
                    previous_line = ""
                else:
                    previous_line = line
            fails_summary += ("".join(lines)).strip()
        fails_summary += "\n```\n"
        if "failed to concretize" in lines[0]:
            fails_summary += "spack failed to concretize specs due to conflicts.\nThis is"
            fails_summary += " likely intentional due to a conflict() in the recipe(s).\n"

    # TODO: Add support for showing details about the failed specs
    # like used deps (cmake version, openssl version, etc.)
    return fails_summary


def generate_build_results(installed, passed, fails, about_build_host) -> str:
    """Generate a report in markdown format for cut-and-paste into the PR comment."""

    build_results = f"\nBuild results{about_build_host}:\n```py\n"
    if installed or passed:
        cmd = ["bin/spack", "find", "--variants", *(installed + passed)]
        build_results += " ".join(cmd) + "\n"
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

    build_results += "\n```\n" + failure_summary(fails)
    build_results += "\nGenerated by "
    git_dir = os.path.dirname(os.path.realpath(__file__))
    err, stdout, stderr = run(["git", "-C", git_dir, "config", "--get", "remote.origin.url"])
    if not err:
        url = stdout.replace("git@github.com:", "https://github.com/").replace(".git", "")
        build_results += url + "/blob/main/"
    build_results += os.path.basename(__file__) + "\n```py\n" + " ".join(sys.argv) + "\n```"
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


def check_approval_and_merge(args, build_results):
    """Check if the PR is/can be approved and merge the PR if all specs passed."""

    if args.approve:
        print("Approve requested, please review the PR diff before merging!")
        spawn("gh", ["pr", "diff"])
        # Check if it is already approved:
        cmd = ["gh", "pr", "view", args.pull_request, "--json", "state", "-q", ".state"]
        exitcode, stdout, stderr = run(cmd)
        if exitcode:
            print(stderr or stdout)
            return exitcode
        if stdout in ["MERGED", "CLOSED"]:
            print("PR is already merged or closed.")
            return stdout == "MERGED"
        exitcode, stdout, stderr = run(
            ["gh", "pr", "view", "--json", "reviews", "-q", ".reviews[].author.login"]
        )
        if exitcode:
            print(stderr or stdout)
            return exitcode
        if stdout:
            print("PR is already approved.")
            print("Approved by:", stdout.replace("\n", " "))

        print("\nBuild results:\n\n")
        print(build_results + "\n\n")

        if (
            args.yes
            or not stdout
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

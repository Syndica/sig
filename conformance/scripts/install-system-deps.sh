#!/usr/bin/env bash
set -euo pipefail

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir

# installs packages in ubuntu.
# can handle any package in the official repos and python311
ubuntu() {
    local python=false
    local normal=()
    for arg in "$@"; do
        case "$arg" in
            python311) python=true ;;
            *) normal+=("$arg") ;;
        esac
    done

    if ! dpkg -s "${normal[@]}" &>/dev/null; then
        sudo apt-get install -y "${normal[@]}"
    fi

    if [[ "$python" == "true" ]]; then
        if ! dpkg -s python3.11 python3.11-dev python3.11-venv &>/dev/null; then
            sudo add-apt-repository ppa:deadsnakes/ppa -y
            sudo apt-get update
            sudo apt-get install -y python3.11 python3.11-dev python3.11-venv
        fi
    fi
}

# installs packages in arch linux.
# can handle any package in the official repos and python311
arch() {
    local python=false
    local normal=()
    for arg in "$@"; do
        case "$arg" in
            python311) python=true ;;
            *) normal+=("$arg") ;;
        esac
    done

    if ! pacman -Qq "${normal[@]}" &>/dev/null; then
        sudo pacman -S --noconfirm "${normal[@]}"
    fi

    if [[ "$python" == "true" ]]; then
        if ! pacman -Qq python311 &>/dev/null; then
            git clone https://aur.archlinux.org/python311.git env/python311
            pushd env/python311
            makepkg -si --noconfirm
            popd
            rm -rf env/python311
        fi
    fi
}

# print a help message if user hasn't provided any arguments
if [ "$#" -eq 0 ]; then
    cat <<-EOF

	Usage: $0 [dependents...]
	    solana-conformance    Install solana-conformance's dependencies.
	    solfuzz-agave         Install solfuzz-agave's dependencies.

	EOF
    exit 1
fi

# detect operating system
. /etc/os-release
case "$ID" in
    ubuntu) func=ubuntu ;;
    arch) func=arch ;;
    *) echo "Unsupported OS: $ID, not installing anything" ;;
esac

# collect the dependents' dependencies
deps=()
for arg in "$@"; do
    case "$arg" in
        solana-conformance) deps+=(git python311) ;;
        solfuzz-agave) deps+=(gcc git cmake) ;;
        *) echo "Unknown dependent: $arg"; exit 1 ;;
    esac
done

# install dependencies
$func "${deps[@]}"

echo Dependencies installed.

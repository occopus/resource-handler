#!/bin/bash

set -e

# This script has three built-in features; others must be implemented manually,
# package-by-package.

# These files to be automatically installed in the config dir.
AUTO_COPY_FILES=''
# If yes, all files are copied to the config dir directly. If no,
# subdirectory structure is built too.
FLAT=yes
# If 'yes', the script will verify and enforce the existence auth_data.yaml. If
# the work tree contains the auth_data file, it is installed automatically.
WITH_AUTH_DATA=yes
AUTH_DATA_FILE="${1:-auth_data.yaml}"

################################################################################

# Find out the full, absolute path of this script's home directory.
# This code is kept only for future reference, 'cd $(dirname $0)' would
# be sufficient.
BASEDIR="$( cd "$(dirname "$0")" && echo "$PWD" )"
cd "$BASEDIR"

PREFIX="$(python -c 'import sys; print sys.prefix')"
CFG_DIR="$PREFIX/etc/occo"

install() {
    cp -v "$1" "${2:-$CFG_DIR}"
}

mkdir -vp "$CFG_DIR"

for FILE in $AUTO_COPY_FILES; do
    if [ $FLAT == yes ]; then
        install "$FILE"
    else
        TARGET="$CFG_DIR/$FILE"
        mkdir -pv "$(dirname "$TARGET")"
        install "$FILE" "$TARGET"
    fi
done

if [ $WITH_AUTH_DATA == yes ]; then
    # It only exists in development work trees, not test deploys -- hopefully!
    [ -f "$AUTH_DATA_FILE" ] && install "$AUTH_DATA_FILE" "$CFG_DIR/auth_data.yaml"

    # Final check if auth_data exists.
    if [ ! -s "$CFG_DIR/auth_data.yaml" ]; then
        echo 'Fatal: Authentication data is not installed; test would fail.' >&2
        exit 1
    fi
fi

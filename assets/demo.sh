#!/usr/bin/env bash
# Records the README demo: types each command like a human, then runs it.
#
# Run from a directory prepared with assets/demo_setup.py:
#   python assets/demo_setup.py demo && cd demo
#   asciinema rec ../assets/demo.cast --cols 100 --rows 40 --overwrite \
#       -c "bash ../assets/demo.sh"
#   python ../assets/retime.py ../assets/demo.cast ../assets/demo.cast
#   npx svg-term-cli --in ../assets/demo.cast --out ../assets/demo.svg \
#       --window --width 100 --height 35 --padding 14
#
# SHARDPIX overrides the binary, e.g. SHARDPIX=../.venv/bin/shardpix.

set -u

SHARDPIX="${SHARDPIX:-shardpix}"

run_typed() {
    local line="$1"
    printf '\033[1;32m$\033[0m '
    sleep 0.5
    for (( i = 0; i < ${#line}; i++ )); do
        printf '%s' "${line:i:1}"
        sleep 0.03
    done
    printf '\n'
    sleep 0.4
    eval "${line/#shardpix/$SHARDPIX}"
    printf '\n'
    sleep 1.5
}

run_typed "shardpix seal docs/notes.pdf photos/*.png -k 3 --passphrase-file key"
run_typed "shardpix unseal sealed/notes.pdf.spx sealed/{coffee,street,astronaut}.png --passphrase-file key"
run_typed "cmp docs/notes.pdf notes.pdf && echo identical"
run_typed "shardpix analyze sealed/street.png"

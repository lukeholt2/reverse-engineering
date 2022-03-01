#!/bin/bash


BINARY="$1"


if [ -z "$BINARY" ]; then
    echo 'Binary Required'
    exit 1;
fi

# find the analyzeHeadless executable
# it's buried in ghidra directory so for now it's safe
# to simple search from the home directory
GHIDRA=$(find ~/ -type f -name 'analyzeHeadless')
# specify the directory containing custom ghidra scripts
SCRIPTPATH=~/reverse-engineering/


$GHIDRA . tmp_proj -import $BINARY -deleteProject -scriptPath $SCRIPTPATH -postScript ./ProjectScript.java



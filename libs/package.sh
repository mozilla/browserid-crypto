#!/bin/bash

echo ''
echo '****Packaging External Dependencies****'
echo ''

PACKAGE="./package.txt"
MINIMAL_PACKAGE="./minimal_package.txt"
OUTPUT="./all.js"
MINIMAL_OUTPUT="./minimal.js"

# go through the dependencies file
if [ ! -f "$PACKAGE" ]; then
    echo "no package file, oh blarg."
    exit 1
fi

if [ -f "$OUTPUT" ]; then
    rm "$OUTPUT"
fi

cat "$PACKAGE" |while read filename; do
    cat "${filename}" >> "$OUTPUT";
done

if [ ! -f "$MINIMAL_PACKAGE" ]; then
    echo "no minimal package file, oh blarg."
    exit 1
fi

if [ -f "$MINIMAL_OUTPUT" ]; then
    rm "$MINIMAL_OUTPUT"
fi

cat "$MINIMAL_PACKAGE" |while read filename; do
    cat "${filename}" >> "$MINIMAL_OUTPUT";
done

#!/bin/bash

echo ''
echo '****Packaging External Dependencies****'
echo ''

PACKAGE="./package.txt"
OUTPUT="./all.js"

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

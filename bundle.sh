#!/bin/sh
##

echo ''
echo '****Bundling VEP for Browser****'
echo ''

INPUT="./bundle.js"
TMP="./tempbundle.js"
OUTPUT="./vepbundle.js"

# package
cd libs
./package.sh

cd ../

# remove the existing file if it exists
if [ -f "$OUTPUT" ]; then
    rm "$OUTPUT"
fi

browserify "$INPUT" -o "$TMP"
cat bundle-prelim.js > "$OUTPUT"
cat "$TMP" >> "$OUTPUT"
rm "$TMP"


#!/bin/sh
##

echo ''
echo '****Bundling VEP for Browser****'
echo ''

INPUT="./bundle.js"
OUTPUT="./vepbundle.js"

# package
cd libs
./package.sh

cd ../

# remove the existing file if it exists
if [ -f "$OUTPUT" ]; then
    rm "$OUTPUT"
fi

browserify "$INPUT" -o "$OUTPUT"


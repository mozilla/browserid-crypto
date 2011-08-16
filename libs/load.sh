#!/bin/sh
##
## for some reason, some of the files are returning 403
## when loaded via wget. Rather than automate the downloads
## let's do this manually for now

WGET=`which wget 2> /dev/null`
if [ ! -x "$WGET" ]; then
    echo "wget not found in your path, can't load resources"
    exit 1
fi

echo ''
echo '****Loading Dependencies****'
echo ''

DEPENDENCIES="./dependencies.txt"
OUTPUT="./all.js"

# go through the dependencies file
if [ ! -f "$DEPENDENCIES" ]; then
    echo "no dependencies file, oh blarg."
    exit 1
fi

`$WGET --input-file=$DEPENDENCIES --output-document=$OUTPUT`


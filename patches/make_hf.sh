#!/bin/bash

DIR=honggfuzz-5a504b49

git clone https://github.com/google/honggfuzz.git $DIR

cd $DIR || exit 1

git checkout 5a504b49fe829a73b6ea88214d8e4bcf3d103d4f

cd - || exit 1

patch -s -p0 < honggfuzz-5a504b49-pastis.patch

cd - || exit 1

make

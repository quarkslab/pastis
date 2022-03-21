# README

Here you'll find the patch files for the modifications introduce to Honggfuzz
to support Pastis.

## Instructions

To apply the pathc run the following command (in this case, for Honggfuzz
version 2.5):

```bash
wget https://github.com/google/honggfuzz/archive/refs/tags/2.5.zip
unzip 2.5.zip
patch -s -p0 < honggfuzz-2.5-pastis.patch
cd honggfuzz-2.5
make all
```

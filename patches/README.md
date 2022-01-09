# README

Here you'll find the patch files for the modifications introduce to Honggfuzz
to support Pastis.

## Instructions

To apply the pathc run the following command (in this case, for Honggfuzz
version 2.4):

```bash
tar xvfz honggfuzz-2.4.tar.gz
patch -s -p0 < <path/to/honggfuzz-2.4-pastis.patch>
cd honggfuzz-2.4
make all
```

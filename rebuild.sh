#!/bin/sh
rm -rf build_dir/target-mipsel_24kec+dsp_uClibc-0.9.33.2/root-ramips/
rm -rf build_dir/target-mipsel_24kec+dsp_uClibc-0.9.33.2/net4g/
make V=s
ls -al bin/ramips


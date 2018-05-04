export CONFIGFLAGS=--host=x86_64-w64-mingw32
export CC=gcc
cd VirusTotal/yara
./bootstrap.sh
unset CC
./configure $CONFIGFLAGS
make -j16
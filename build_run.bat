@echo off

set CXX=C:\tools\toolchain-windows\toolchain-arm64-21\bin\aarch64-linux-android33-clang++.cmd

set OUTDIR=build

del %OUTDIR% /q
mkdir %OUTDIR%

call buildtest.bat
del /q test_binso.hpp
python transChdr.py %OUTDIR%\test.so > test_binso.hpp
call buildmapper.bat


adb push build/ElfMapper /data/local/tmp/ElfMapper
adb shell chmod +x /data/local/tmp/ElfMapper
adb shell /data/local/tmp/ElfMapper

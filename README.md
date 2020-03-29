canaryscan: Scan this process' memory map looking for its stack canary.
=======================================================================
Scan this process' memory map looking for its canary.
The canary might be generated via the kernel upon binary load, and passed
to the userland runtime loader (glibc's rtld.c aka ld) via an elf aux
field.

This is similar to https://github.com/enferex/homingcanary
HomingCanary scans other processes but requires root access.

Note that this is designed for x86 64bit Linux binaries.

Use Cases
---------
* Identify if some memory regions are caching the canary value.
* Run this multiple times to collect numerous canary values.  For science!

Building
--------
1. Create a build directory. `mkdir canaryscan/build`
1. From the just created build directory, invoke cmake with the path to the
   libsprinkles sources.
   `cd canaryscan/build; cmake ../ -DCMAKE_BUILD_TYPE=Release`
1. Invoke `make` to build this bad boy.

Contact
-------
Matt Davis: https://github.com/enferex

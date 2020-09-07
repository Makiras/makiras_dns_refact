<!--
 * @Author: Makiras
 * @Date: 2020-07-29 16:01:41
 * @LastEditTime: 2020-08-06 22:08:27
 * @LastEditors: Makiras
 * @Description: 
 * @FilePath: \makiras_dns_refact\README.md
 * @Licensed under the Apache License, Version 2.0 (the "License");
 * @Copyright 2020 @Makiras
-->
# makiras_dns_refactor

## How to Build

### Windows

#### Build Environment  

MSYS2 terminal 
```bash
pacman -Syu
pacman -S vim git 
pacman -S mingw-w64-x86_64-toolchain
pacman -S mingw-w64-x86_64-libuv mingw-w64-x86_64-curl
# change /etc/pacman.d/mirrorlist.mingw64 for better speed
```

For entering the msys2 terminal 
```
./msys64.bat
# or
bash ./msys64.bat
```

#### How to Build
```
make
make clean
```

### Linux

TBD
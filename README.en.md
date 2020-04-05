# raspberrypi-kernel

#### Description

The openEuler-1.0-LTS kernel for running on Raspberry Pi, located at branch [openEuler-1.0-LTS-raspi](https://gitee.com/openeuler/raspberrypi-kernel/tree/openEuler-1.0-LTS-raspi/).

This repository is built based on [openEuler-1.0-LTS kernel](https://gitee.com/openeuler/kernel/tree/openEuler-1.0-LTS/) and [Raspberry Pi kernel](https://github.com/raspberrypi/linux/tree/rpi-4.19.y).

#### Architecture Requirements

Hardware: Raspberry Pi 3B/3B+/4B.

Architecture: AArch64.

#### Compiling

Compile kernel and kernel modules.

1.  Prepare compile environment

OS: openEuler or Centos 7/8;

Architecture: ARM.

For example, you can use [QEMU](https://www.qemu.org/) to build ARM system emulation.

2.  Download source

`git clone https://gitee.com/openeuler/raspberrypi-kernel.git`

3.  Go to the source directory and checkout the openEuler-1.0-LTS-raspi branch

`cd raspberrypi-kernel`

`git checkout -b openEuler-1.0-LTS-raspi origin/openEuler-1.0-LTS-raspi`

4.  Load default settings

`make openeuler-raspi_defconfig`

5.  Compile kernel

`make ARCH=arm64 -j4`

6.  Create directory for compiling kernel modules

`mkdir ../output`

7.  Compile kernel modules

`make INSTALL_MOD_PATH=../output/ modules_install`

Now, the kernel compilation is complete.

#### Installation

Refer to `https://gitee.com/openeuler/raspberrypi` for details about how to use this compiled kernel to build openEuler image for Rasberry Pi.

#### Contributions

1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request


#### Gitee Feature

1.  You can use Readme\_XXX.md to support different languages, such as Readme\_en.md, Readme\_zh.md
2.  Gitee blog [blog.gitee.com](https://blog.gitee.com)
3.  Explore open source project [https://gitee.com/explore](https://gitee.com/explore)
4.  The most valuable open source project [GVP](https://gitee.com/gvp)
5.  The manual of Gitee [https://gitee.com/help](https://gitee.com/help)
6.  The most popular members  [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)


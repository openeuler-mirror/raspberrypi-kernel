# raspberrypi-kernel

#### Description

The 4.19.90 kernel for running on Raspberry Pi, branch master is the branch on development.

This repository is based on [4.19.90-2003.4.0](https://gitee.com/openeuler/kernel/tree/openEuler-1.0-LTS/) version kernel which is built into openEuler 20.03 LTS, and is merged with the 4.19.y branch of [Raspberry Pi kernel](https://github.com/raspberrypi/linux/tree/rpi-4.19.y).

#### Architecture Requirements

Hardware: Raspberry Pi 3B/3B+/4B.

Architecture: AArch64.

#### Compiling

Compile kernel and kernel modules.

1.  Prepare compile environment

OS: openEuler or CentOS 7/8;

Architecture: AArch64.

You follow the documents of [raspberrypi](https://gitee.com/openeuler/raspberrypi/blob/master/README.en.md) to cross-compile this kernel. 

2.  Download source

`git clone git@gitee.com:openeuler/raspberrypi-kernel.git`

3.  Load default settings

`make openeuler-raspi_defconfig`

4.  Compile kernel

`make ARCH=arm64 -j4`

5.  Create directory for compiling kernel modules

`mkdir ../output`

6.  Compile kernel modules

`make INSTALL_MOD_PATH=../output/ modules_install`

Now, the kernel compilation is complete.

#### Installation

Refer to [raspberrypi Repository](https://gitee.com/openeuler/raspberrypi) for details about how to use this compiled kernel to build openEuler image for Rasberry Pi.

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


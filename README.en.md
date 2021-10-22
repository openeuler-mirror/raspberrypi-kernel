# raspberrypi-kernel

English | [简体中文](./README.md)

#### Description

The kernel for running on Raspberry Pi.

This repository is based on [openEuler kernel](https://gitee.com/openeuler/kernel) which is merged patches of [Raspberry Pi kernel](https://github.com/raspberrypi/linux).

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

    You need download different branches of different repositories according to the kernel version.

    1.  Kernel 5.10

        - openEuler 21.09: `git clone git@gitee.com:openeuler/raspberrypi-kernel.git -b openEuler-21.09 && cd raspberrypi-kernel`
        - openEuler 21.03: `git clone git@gitee.com:openeuler/kernel.git -b openEuler-21.03 && cd kernel`

    2.  Kernel 4.19

        - openEuler 20.03 LTS: `git clone git@gitee.com:openeuler/raspberrypi-kernel.git -b openEuler-20.03-LTS && cd raspberrypi-kernel`
        - openEuler 20.09: `git clone git@gitee.com:openeuler/raspberrypi-kernel.git -b openEuler-20.09 && cd raspberrypi-kernel`

3.  Load default settings

    You need load different settings according to the kernel version.

    1.  Kernel 5.10

        - openEuler 21.09: `make bcm2711_defconfig`
        - openEuler 21.03: `make bcm2711_defconfig`

    2.  Kernel 4.19

        - openEuler 20.03 LTS: `make openeuler-raspi_defconfig`
        - openEuler 20.09: `make openeuler-raspi_defconfig`

    The corresponding defconfig file is in . /arch/arm64/configs.

4.  Compile kernel

    `make ARCH=arm64 -j4`

5.  Create directory for compiling kernel modules

    `mkdir ../output`

6.  Compile kernel modules

    `make INSTALL_MOD_PATH=../output/ modules_install`

Now, the kernel compilation is complete.

#### Installation

Refer to [raspberrypi Repository](https://gitee.com/openeuler/raspberrypi) for details about how to use this compiled kernel to build openEuler image for Raspberry Pi.

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


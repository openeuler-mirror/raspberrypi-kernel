# raspberrypi-kernel

#### 介绍

适用于树莓派的 openEuler-1.0-LTS 内核源码，位于本仓库分支：[openEuler-1.0-LTS-raspi](https://gitee.com/openeuler/raspberrypi-kernel/tree/openEuler-1.0-LTS-raspi/)。

本仓库基于 [openEuler-1.0-LTS 内核](https://gitee.com/openeuler/kernel/tree/openEuler-1.0-LTS/) 和 [树莓派内核](https://github.com/raspberrypi/linux/tree/rpi-4.19.y)。


#### 硬件要求

硬件：树莓派 3B/3B+4B。

架构：AArch64。

#### 编译

编译内核和内核模块。

1.  准备编译环境

操作系统：openEuler 或 Centos 7/8；

架构：ARM。

可以使用 [QEMU](https://www.qemu.org) 模拟器搭建 ARM 运行环境。

2.  下载源码

`git clone https://gitee.com/openeuler/raspberrypi-kernel.git`

3.  进入源码目录并切换到openEuler-1.0-LTS-raspi分支

`cd raspberrypi-kernel`

`git checkout -b openEuler-1.0-LTS-raspi origin/openEuler-1.0-LTS-raspi`

4.  载入默认设置

`make openeuler-raspi_defconfig`

5.  编译内核

`make ARCH=arm64 -j4`

6.  创建编译内核模块目录

`mkdir ../output`

7.  编译内核模块

`make INSTALL_MOD_PATH=../output/ modules_install`

至此，内核编译完成。

#### 使用说明

利用上面编译好的内核来构建镜像，具体文档参见`https://gitee.com/openeuler/raspberrypi`。

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


#### 码云特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  码云官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解码云上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是码云最有价值开源项目，是码云综合评定出的优秀开源项目
5.  码云官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  码云封面人物是一档用来展示码云会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)


---
layout : post
title : Linux内核设计的艺术 读书笔记一
categories : Linux
tags : Linux-Kernel
---

# 系列文章
1. [Linux内核设计的艺术 读书笔记一](/Linuxneiheshejideyishu1)
2. [Linux内核设计的艺术 读书笔记二](/Linuxneiheshejideyishu2)
3. [Linux内核设计的艺术 读书笔记三](/Linuxneiheshejideyishu3)
4. [Linux内核设计的艺术 读书笔记四](/Linuxneiheshejideyishu4)
5. [Linux内核设计的艺术 读书笔记五](/Linuxneiheshejideyishu5)
6. [Linux内核设计的艺术 读书笔记六](/Linuxneiheshejideyishu6)
7. [Linux内核设计的艺术 读书笔记七](/Linuxneiheshejideyishu7)
8. [Linux内核设计的艺术 读书笔记八](/Linuxneiheshejideyishu8)

!TOC

#第一章 从开机加电到执行main函数之前的过程
---

##1.1 启动BIOS，准备实模式下的中断向量表和终端服务程序

###BIOS的启动原理
一台电脑在开机加电的一瞬间，内存中什么程序也没有，没有任何程序执行，如何执行BIOS呢？这样，使用CPU硬件逻辑设计为加电的瞬间将`CS`的值设置为`0xFFFF`，`IP`的值设为`0x0000`，这样`CS:IP`就指向了`0xFFFF0`这个位置，而这个位置就是BIOS程序第一条指令所在的位置，代码开始运行。当然这只是80x86系列CPU的启动模式，也就是平时买电脑为什么主板支持什么CPU的原因。
>上述的操作是一个完全的硬件操作，如果最后得到的地址上没有可执行代码，计算机就此死机。

###BIOS在内存中加载中断向量表和中断服务程序
BIOS程序的代码量并不大，但是很精深，被固化在一块很小的ROM芯片中。不同主板的BIOS程序也是不一样的，作者选用的一个8KB的BIOS程序，所占地址段为`0xFE000-0xFFFFF`。当`CS:IP`就指向了`0xFFFF0`这个位置，BIOS启动，随着执行，会检查显卡，内存等等内容，也就是我们平时开机上经常显示的内容。在此期间，BIOS创建中断向量表和中断服务程序，这是至关重要的。BIOS程序在内存开始的地方`0x00000`用1KB的空间`0x00000~0x003FF`构建中断向量表，并在紧挨着它的位置用256字节`0x00400~0x004FF`空间构建BIOS的数据区，在大约56KB以后的位置`0x0E2CE`加载了8KB左右的与中断向量表相应的若干中断服务程序。
>关于中断向量表，中断服务程序请看 [这里](http://baike.baidu.com/link?url=_LdP-Q-Lj42LSncMjgileGKZXzQwDryAsUYYmFvMuhzsRoHstcc8ZVj_OLvSpIBxI_2NgBG9hWwaxCWTr_o0WhAgFbXdPO4nMa8Qpbz4qDkuedOSYLnYYDc9SnYk8UBV)

## 1.2 从启动盘加载操作系统到内存
对于Linux0.11来说，计算机分三次加载操作系统代码，第一批由BIOS中断int 0x19把第一扇区bootsect的内容加载到内存，第二批和第三批在bootsect的指挥下，分别把其后的4个扇区和随后的240个扇区内容加载至内存。对于其他的操作系统，大致上也是一直的，先由BIOS将bootsect加载至内存，然后bootsect根据策略加载其他部分。

###加载第一部分代码---引导程序（bootsect）


## 1.3 为执行32位的main函数做过度工作


#参考文献
---
1. Linux内核设计的艺术 新设计团队 杨力祥
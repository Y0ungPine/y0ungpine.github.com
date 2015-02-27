---
layout : post
title : GitHub 记录
categories : 混合
tags : GitHub
---
!TOC

#GitHub SSH 连接
---
1.检测是否有SSH keys

```
$ ls -al ~/.ssh
# Lists the files in your .ssh directory, if they exist
```
默认的公钥名称为：

* id_dsa.pub
* id_ecdsa.pub
* id_ed25519.pub
* id_rsa.pub

2.如果没有SSH keys，则生成SSH keys。

```
$ ssh-keygen -t rsa -C "your_email@example.com"
# Creates a new ssh key, using the provided email as a label
# Generating public/private rsa key pair.
# Enter file in which to save the key (/Users/you/.ssh/id_rsa): [Press enter]
```
因为可能需要看指纹识别码，所以要输入密码，这个密码不是GitHub的密码。

```
# Enter passphrase (empty for no passphrase): [Type a passphrase]
# Enter same passphrase again: [Type passphrase again]
```
接下来输入秘钥的名称，可以自己确定，也可以使用默认的名称。

```
# Your identification has been saved in /Users/you/.ssh/id_rsa.
# Your public key has been saved in /Users/you/.ssh/id_rsa.pub.
# The key fingerprint is:
# 01:0f:f4:3b:ca:85:d6:17:a1:7d:f0:68:9d:f0:a2:db your_email@example.com
```
将key加入自己的ssh-agent中。

```
# start the ssh-agent in the background
$ eval "$(ssh-agent -s)"
# Agent pid 59566
$ ssh-add ~/.ssh/id_rsa
```

3.向自己的用户添加SSH key

拷贝公钥到粘贴版。

```
$ pbcopy < ~/.ssh/id_rsa.pub
# Copies the contents of the id_rsa.pub file to your clipboard
```
添加公钥到GitHub设置中。

Setting -> SSH keys -> Add SSH key -> 输入公钥和关于此公钥的描述 -> Add key

4.测试连接

命令行中输入：

```
$ ssh -T git@github.com
# Attempts to ssh to GitHub
```
得到这样的输入是正确的：

```
# The authenticity of host 'github.com (207.97.227.239)' can't be established.
# RSA key fingerprint is 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48.
# Are you sure you want to continue connecting (yes/no)?`
```
只要输入yes，就能够连接了，如果连接后得到的结果是：

```
# Hi username! You've successfully authenticated, but GitHub does not
# provide shell access.
```
那么连接就成功了，可以在本地连接GitHub了。

#使用git第一次创建项目
---
使用

```
$ ssh -T git@github.com
```
连接了Github之后，首先创建一个新的项目。

```
$ makdir ~/hello-world     //创建一个目录hello-world
$ cd ~/hello-world         //进入这个项目
$ git init                 //初始化目录，就创建了项目hello-world
$ touch README             //创建一个文件
$ git add README           //将次文件加入git控制中
$ git commit -m 'first commit'      //提交更新，并注释信息“first commit” 
$ git remote add origin git@github.com:yourname/hello-world.git   //连接远程github项目  
$ git push -u origin master         //将本地项目更新到github项目上去
```

#Git暂存区
---
暂留


#命令记录
---
添加文件到暂存区

```
git add  <文件、目录>    //将文件或目录加入暂存区
```

提交命令

```
git commit //不带参数的命令，Git会启动编辑器来编辑提交留言。
git commit –m "提交留言" 
git commit -v //参数v：把要提交的内容与版本库中的比较结果添加到编辑器中。
git commit -a //参数a：把工作目录树中当前所有的修改提交到版本库中。
```

迁出命令

```
git checkout <文件、目录>    //迁出文件，回覆盖本地修改
```

查看修改内容

```
git status //查看工作目录树中所有的变动
git diff   //显示工作目录树、暂存区及版本库之间的差异。不带参数的git diff，将显示工作目录树中未被暂存（当然还没有提交）的改动。（比较的是工作目录树与暂存区）。
git diff --cached //添加参数--cached，是比较暂存区和版本库之间的区别。
git diff HEAD     //添加参数HEAD，可以比较工作目录树（包括暂存的和未暂存的修改）与版本库之间的差别。HEAD关键字指的是当前所在分支末梢的最新提交（也就是版本库中该分支上的最新版本）。
```
管理文件

```
git mv <原文件名称> <新文件名称>  //文件的重命名与移动.
git mkdir 
git rm 
git ls-files
等

```

#可能遇到的错误
---
1.在执行

```
$ git remote addorigin git@github.com:yourname/hello-world.git
```
错误提示：fatal: remote origin already exists.

解决方案：执行

```
$ git remote rm origin
```
后，再执行上条命令。

2.在执行

```
$ git push origin master
```
错误提示：error:failed to push som refs to.
解决方案：执行

```
$ git pull origin master // 先把远程服务器github上面的文件拉下来，再push 上去。
```

#参考
---
* [Resize](http://resizesafari.com "a Safari extension")



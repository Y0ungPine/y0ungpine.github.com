---
layout : post
title : Antlrworks2 “could not install some modules:org.apache.commons.io” Bug 解决
categories : 混合
tags : Antlrworks2
---
!TOC

以前碰到过这个问题，解决过一次，但是今天又给弄坏了，想了半天想不起来上次是怎么解决的，说明还是得记录下来这些解决方式。

这是Antlrworks 2.1版本出现的一个bug，当你把Antlrworks目录换一个地方，或者删掉以后重新下载一个使用，只要不在同一个目录，就会有报错代码如下：

```
Warning - could not install some modules:
	org.apache.commons.io - org.netbeans.InvalidException: Netigso: /Users/yourname/不用备份的资料/antlrworks2副本/ide/modules/org-apache-commons-io.jar: Not found bundle:org.apache.commons.io
java.io.IOException: Referenced file does not exist: /Users/yourname/Tools/antlrworks2/ide/modules/org-apache-commons-io.jar
	at org.apache.felix.framework.cache.BundleArchive.createRevisionFromLocation(BundleArchive.java:852)
	at org.apache.felix.framework.cache.BundleArchive.reviseInternal(BundleArchive.java:550)
	at org.apache.felix.framework.cache.BundleArchive.<init>(BundleArchive.java:226)
	at org.apache.felix.framework.cache.BundleCache.getArchives(BundleCache.java:247)
	at org.apache.felix.framework.Felix.init(Felix.java:694)
	at org.netbeans.core.netigso.Netigso.prepare(Netigso.java:166)
	at org.netbeans.NetigsoHandle.turnOn(NetigsoHandle.java:127)
	at org.netbeans.ModuleManager.enable(ModuleManager.java:1176)
	at org.netbeans.ModuleManager.enable(ModuleManager.java:1011)
	at org.netbeans.core.startup.ModuleList.installNew(ModuleList.java:340)
	at org.netbeans.core.startup.ModuleList.trigger(ModuleList.java:276)
	at org.netbeans.core.startup.ModuleSystem.restore(ModuleSystem.java:301)
	at org.netbeans.core.startup.Main.getModuleSystem(Main.java:181)
	at org.netbeans.core.startup.Main.getModuleSystem(Main.java:150)
	at org.netbeans.core.startup.Main.start(Main.java:307)
	at org.netbeans.core.startup.TopThreadGroup.run(TopThreadGroup.java:123)
	at java.lang.Thread.run(Thread.java:745)
```

**解决的方法是**将缓存文件删掉，目录在这个地方：

```
windows 
C:\Users\<YouName>\AppData\Roaming\.antlrworks2 
Mac 
/Users/<USER>/Library/Application\ Support/antlrworks2
```

2.2版本的Antlrworks作为NetBeans的一个插件出现的，没有上面的这个bug。

#参考文献
---
1. [https://github.com/tunnelvisionlabs/antlrworks2/issues/17](https://github.com/tunnelvisionlabs/antlrworks2/issues/17)
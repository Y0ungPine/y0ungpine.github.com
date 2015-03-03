---
layout : post
title : GitHub Page、jekyll、markdown增加目录
categories : 混合	
tags : GitHub Jekyll Markdown
---

修改**_config.yml**文件中的markdown属性为:

```
markdown: rdiscount
rdiscount: 
  extensions:
    - autolink
    - footnotes
    - smart
    - generate_toc
  toc_token: "! TOC"  //将空格去掉，因为没空格的话这个页面显示回出错
```
在使用的时候，在Markdown中需要增加目录的地方加入**!TOC**，就可以调用目录了。
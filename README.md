# Log4j2Scan

魔改于 https://github.com/whwlsfb/Log4j2Scan

增加了新的bypass waf  payload

增加了 param Name ， json special unicode payload，  path 的扫描

增加了避免重复扫描的 Tree算法

添加了对param name 加白的功能

优化了代码逻辑





# ChangeLog
### 2021/12/12
##### v0.6
1. 加入静态文件过滤。
2. 加入多POC支持，共十种poc变种，默认启用POC1~4。
3. 加入burpcollaborator的dnslog支持，默认使用dnslog.cn。
### 2021/12/11
##### v0.5
1. 加入Header的fuzz功能。
##### v0.4
1. 加入RC1补丁的绕过poc。

# 效果截图

![](screenshots/detected.png)


# 修改Dnslog平台

因为没有太多的时间去开发界面，有修改dnslog平台需求的可以先临时使用以下方法手动切换Dnslog平台为`ceye.io`

1. 下载源码使用任意IDE打开。
2. Ceye.java 里需要修改"rootDomain"、"token"的值，对应ceye的profile页面中的Identifier、API Token。
3. Log4j2Scanner.java里需要将`this.dnslog = new DnslogCN();`修改为`this.dnslog = new Ceye();`
4. 使用`mvn package`重新打包项目。

# 鸣谢
插件中部分代码借鉴于以下项目

https://github.com/pmiaowu/BurpShiroPassiveScan/

## WMImplant
* WMImplant项目来源于 https://github.com/FortyNorthSecurity/WMImplant
* 主要做了以下更新:
    * 远程COM劫持
    * WMI事件订阅
* 并做了多项修改和优化
* WMI-EventSubscription：WMI的事件订阅，用于持久化
* Remote-ComHijack：远程COM劫持

## WMI-EventSubscription
* WMI-EventSubscription:设置WMI事件订阅
* WMI-ShowEventSubscription：展示已经存在的事件订阅
* WMI-DelEventSubscription：删除事件订阅

## Remote-ComHijack
* Remote-ComHijack is a COM hijacking tool based on WMI，This tool has three main functions
    * Find-CLSID:Find suspicious CLSID 
   ![mark](http://hacky.wang/blog/20220613/y2z1Qbp8REli.png?imageslim)
    * Set-COM:Set COM hijacking by modifying the registry's InprocServer32 or LocalServer32 key
   ![mark](http://hacky.wang/blog/20220613/NxBrH0UCSHCt.png?imageslim)
   ![mark](http://hacky.wang/blog/20210925/YurWytrBbdEl.png?imageslim)
    * Remote-CreateInstance：Remotely instantiate COM
   ![mark](http://hacky.wang/blog/20220613/aAT1rgVCp4TI.png?imageslim)
   ![mark](http://hacky.wang/blog/20210925/eOowQbECzCJG.png?imageslim)
* Remote-ComHijack has been integrated into the WMImplant

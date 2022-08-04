# 评测端安装指南

评测端仅支持Linux系统，内核版本在5.10以上，较低版本可能无法编译。

暂仅支持x86_64和i386架构的处理器，其它类型需要修改相应程序代码。

## 设置内核引导命令行

COJ在线评测系统使用 `cgroup V1` 限制、测量程序使用的资源数量（如：内存、进程数量、CPU 时间），其中一些功能未在 `cgroup V2` 中实现。在一些较新的系统中需要关闭 ``cgroup V2`。

你需要编辑 Linux 内核的引导命令行，添加以下参数：

```
cgroup_enable=memory swapaccount=1
```

在一些较新的 GNU/Linux 发行版中（如Debian 11）还需要添加以下内容

```
systemd.unified_cgroup_hierarchy=0
```

在采用GRUB引导的系统中可以通过编辑`/etc/default/grub`文件来实现。

找到

```
GRUB_CMDLINE_LINUX_DEFAULT="..."
```

在引号内添加

```
cgroup_enable=memory swapaccount=1 systemd.unified_cgroup_hierarchy=0
```

如：

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet cgroup_enable=memory swapaccount=1 systemd.unified_cgroup_hierarchy=0"
```

然后运行命令

```
PATH=$PATH:/sbin update-grub
```

运行完成后重启系统。

## 准备 chroot 根文件系统

使用 root 用户运行 `gen-sandbox.sh` 下载并安装即可。安装完成后预计占用空间800MiB。

## 编译评测程序

待完成

## 设置评测帐号

待完成

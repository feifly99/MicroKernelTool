2024/9/9：修复了关机蓝屏的BUG，正确地释放了引用计数；
2024/9/8：新增进程模块遍历，基于PEB->LDR->InLoadOrderModuleListAddress硬编码指针实现；
2024/9/7：新增进程隐藏，基于断PE链实现；
2024/9/3：驱动正常运行，但是一关机就会蓝屏，蓝屏代码为REFERENCE_BY_POINTER。

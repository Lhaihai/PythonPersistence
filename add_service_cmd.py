#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.05
# @Author  : Lhaihai
# @File    : new_service_cmd.py
# @Software: PyCharm
# @Blog    : http://blog.Lhaihai.wang
"""
    Description : 通过 CMD 创建服务
"""

from logger import factory_logger
logger = factory_logger('添加服务')
import subprocess
from func import content_decode
from startup import set_user,clear_user
import sys,os

def add_service_cmd(cmd,service):
    command = 'sc create {} binpath= "cmd.exe /k {}" start= "auto" obj= "LocalSystem"'.format(service,cmd)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    if '5' in rr:
        logger.error('需要管理员权限！')
        return
    elif 'CreateService' in rr:
        set_user('sc start '+service)
        logger.info('创建服务成功')

def add_service_powershell(cmd,service):
    command = 'powershell.exe New-Service -Name "{}" -BinaryPathName "{}" -Description "PentestLaboratories" -StartupType Automatic'.format(service,cmd)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    if 'PermissionDenied' in rr:
        logger.error('需要管理员权限！')
        return
    elif 'DisplayName' in rr:
        set_user('sc start '+service)
        logger.info('创建服务成功')

def delete_service(service):
    command = 'sc delete {}'.format(service)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.debug(rr)
    clear_user()

def start_service(service):
    command = 'sc start {}'.format(service)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.debug(rr)

def stop_service(service):
    command = 'sc stop {}'.format(service)
    r = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rr = content_decode(r.stdout)
    logger.debug(rr)

if __name__ == '__main__':
    # add_service_cmd('c:\\64.exe','pentestlab')
    # add_service_powershell('c:\\64.exe','pentestlab')
    # start_service('pentestlab')
    # stop_service('pentestlab')
    # delete_service('pentestlab')
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action == 'set' and len(sys.argv) == 4:
        cmd = sys.argv[2]
        if ':' not in cmd and '\\' not in cmd:
            path = os.getcwd() + '\\' + cmd
            if os.path.exists(path):
                add_service_cmd(path,sys.argv[3])
            else:
                logger.error(cmd + '文件不存在')
        else:
            add_service_cmd(cmd,sys.argv[3])

    elif action == 'clear' and len(sys.argv) == 3:
        service = sys.argv[2]
        delete_service(service)
    elif action == 'start' and len(sys.argv) == 3:
        service = sys.argv[2]
        start_service(service)
    elif action == 'stop' and len(sys.argv) == 3:
        service = sys.argv[2]
        stop_service(service)
    else:
        print('add_service_cmd.exe set cmd servicename ')
        print('add_service_cmd.exe clear servicename')
        print('add_service_cmd.exe start servicename')
        print('add_service_cmd.exe stop servicename')

#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.05
# @Author  : Lhaihai
# @File    : func.py
# @Software: PyCharm
# @Blog    : http://blog.Lhaihai.wang
"""
    Description : 
"""

def content_decode(content):
    raw_content = content
    try:
        content = raw_content.decode("utf-8")
    except UnicodeError:
        try:
            content = raw_content.decode("gbk")
        except UnicodeError:
             try:
                content = raw_content.decode("gb2312")
             except UnicodeError:
                 try:
                    content = raw_content.decode("big5")
                 except:
                    print("DecodeHtmlError")
    return content
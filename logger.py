#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020.02.04
# @Author  : Lhaihai
# @File    : logger
# @Software: PyCharm
# @Blog    : http://blog.Lhaihai.wang
"""
    Description : 
"""
import logging

def factory_logger(name):

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    DATE_FORMAT = "%Y-%d-%m %H:%M:%S"

    # create formatter
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)-5s - %(message)s",DATE_FORMAT)

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    return logger
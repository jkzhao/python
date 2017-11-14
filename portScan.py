#!/usr/bin/python
#-*- coding:utf-8 -*-

#-------------------------------------------------------------------------------
# Name:         portScan.py
# Purpose:      port scan using python
# Author:       Zhao Jiankai
# Created:      22/09/2016
# Copyright:    Copyright © 2016 Wisedu. All Rights Reserved.
# Licence:      Free to use!
# Version:      alpha!!! (0.1)
#-------------------------------------------------------------------------------

import sys
import nmap
 
'''
    端口扫描
'''

def getMAC():
    "获得MAC地址"
    for k,v in a['scan'].iteritems():
        if str(v['status']['state']) == 'up':
            #print str(v)
            print('MAC ADDRESS: %s' %  str(v['addresses']['mac']))
            #macAddress=str(v['addresses']['mac']
            #print('MAC ADDRESS: %s' %  macAddress)
            #print('Vendor: %s' %  str(v['vendor']["str(v['addresses']['mac'])"]))

def scanPort():
    "扫描主机和端口" 
    for host in nm.all_hosts():         #遍历扫描主机
        print('-----------------主机和端口扫描结果----------------------------')
        print('Host: %s (%s)' % (host,nm[host].hostname()))        #输出主机及主机名
        getMAC()    #输出MAC地址
        print('State: %s' % nm[host].state())                  #输出主机状态信息，如up，down
        for proto in nm[host].all_protocols():                  #遍历扫协议，如tcp，udp
            print('---------------------------')
            print('Protocol: %s' %proto)                       #输入协议名
        
            ports = nm[host][proto].keys()          #获取协议的所有扫描端口,输出为字典形式
            sorted(ports)                           #端口列表排序
            for port in ports:          #遍历端口及输出端口与状态
                print('port: %s \tstate: %s \tservice: %-40s reason: %s \tversion: %s' % (port,nm[host][proto][port]['state'],nm[host][proto][port]['product'],nm[host][proto][port]['reason'],nm[host][proto][port]['version']))
    
    print('')

def help():
    "使用帮助信息"
    print "Usage: example 192.168.1.0/24"
    sys.exit(0)

if __name__ == "__main__":
    scan_list = []
    input_date = raw_input('please input hosts and ports:')
    scan_list = input_date.split(' ')

    if len(scan_list)!=1:
        help()

    hosts = scan_list[0]     #接受用户输入的主机

    try :
        nm = nmap.PortScanner()     #创建端口扫描对象
    except nmap.PortScannerError :
        print('nmap not found',sys.exc_info()[0])   #!!
        sys.exit()
    except :
        print('unexpected error:',sys.exc_info()[0])
        sys.exit()

    try:
        #调用扫描方法，参数指定扫描主机hosts，nmap扫描命令行参数arguments
        a=nm.scan(hosts=hosts,arguments=' -v -sV --version-light --reason -p '+'1-65535')
    except Exception as e:
        print('scan error:'+str(e))

    sys.stdout = open('/tmp/nmap.txt', 'a')
    scanPort() #扫描端口


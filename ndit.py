#!/usr/bin/env python3

"""
Network Device Inventory Tool
"""

__author__ = 'Sergey Andreev (sa@itsens.pro)'

import sys
import argparse
import re
import ipaddress
import socket
import threading
import queue
import paramiko  # дописать проверку импорта

MAX_THREADS = 10
cisco_dev_list = queue.Queue()


class CiscoDevice:

    def __init__(self, ip_addr, port):
        self.ip_address = str(ip_addr)
        self.port = port
        self.family = "n/a"
        self.model = "n/a"
        self.sn = "n/a"
        self.ios_ver = "n/a"

    def inventory(self, user, secret):
        regex_ios_ver = re.compile('(Cisco IOS Software,).*')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Accept all unknown keys
        client.connect(self.ip_address, self.port, user, secret, timeout=1)
        stdin, stdout, stderr = client.exec_command('show version')
        data = stdout.read() + stderr.read()
        data = data.decode()
        self.ios_ver = regex_ios_ver.match(data).group().strip('\r\n')

        return 0


class Inventor(threading.Thread):

    def __init__(self, thread_num, que, args):
        threading.Thread.__init__(self)
        self.thread_num = thread_num
        self.q = que
        self.args = args

    def run(self):
        print("Thread %s started", self.thread_num)
        while not self.q.empty():
            ip_addr = self.q.get()
            response = self.port_check(ip_addr, self.args.port)
            if response:
                is_cisco = CiscoDevice(ip_addr, self.args.port)
                if is_cisco:
                    cisco_device = CiscoDevice(ip_addr, self.args.port)
                    cisco_device.inventory(self.args.user, self.args.secret)
                    cisco_dev_list.put(cisco_device)

        #print("Number of threads", threading.active_count())
        print("Thread %s stoped", self.thread_num)

    def ssh_vendor_check(self, response_sign):
        """

        :param response_sign:
        :return: True if SSH vendor is Cisco, else False
        """
        rx_cisco = re.compile(b'SSH-[12]\.[0-9]{1,2}-Cisco-[0-9]\.[0-9]{1,2}')
        if rx_cisco.match(response_sign):
            is_cisco = True
        else:
            is_cisco = False

        return is_cisco

    def port_check(self, target, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((target, port)) == 0:
            response = s.recv(512)
            s.close()
        else:
            s.close()
            response = False

        return response


def create_parser():

    parser = argparse.ArgumentParser(prog="CSPIT 1.0", description="Cisco SSH Python Inventory Tool")
    parser.add_argument("-t", "--target", action="store", required=True, help="IP address|range")
    parser.add_argument("-p", "--port", action="store", default=22, help="SSH port")
    parser.add_argument("-u", "--user", action="store", required=True, help="SSH User")
    parser.add_argument("-s", "--secret", action="store", required=True, help="SSH Password")

    return parser


def main(argv):
    """
    Main program

    :param argv: sys.argv params
    :return:
    """
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])

    q = queue.Queue()
    target = ipaddress.IPv4Network(args.target)
    for ip_addr in target:
        ip_addr = str(ipaddress.IPv4Address(ip_addr))
        q.put(ip_addr)
    #print(q)

    thread_list = []
    for x in range(MAX_THREADS):
        inventory = Inventor(x+1, q, args)
        thread_list.append(inventory)

    for x in thread_list:
        x.start()

    for x in thread_list:
        x.join()

    print(cisco_dev_list)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print("/n")
        print("ERROR: Keyboard Interrupt")
        sys.exit(0)

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

# Constants
MAX_THREADS = 10

# Global vars
cisco_dev_list = queue.Queue()


class CiscoDevice:

    def __init__(self, ip_addr, port):
        self.ip_address = str(ip_addr)
        self.port = port
        self.status = ""
        self.family = ""
        self.model = ""
        self.sn = ""
        self.ios_ver = ""

    def inventory(self, user, secret):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Accept all unknown keys
        try:
            client.connect(self.ip_address, self.port, user, secret, timeout=5)
            self.status = "Ok"
        except paramiko.AuthenticationException:
            self.status = "Authentication failed!"
            return 1

        self._get_ios_ver(client)

        return 0

    def _get_ios_ver(self, client):
            regex_ios_ver = re.compile('(Cisco IOS Software,).*')
            stdin, stdout, stderr = client.exec_command('show version')
            data = stdout.read() + stderr.read()
            data = data.decode()
            self.ios_ver = regex_ios_ver.match(data).group().strip('\r\n')


class Reporter:

    def __init__(self, cisco_devices):
        self.cisco_devices = cisco_devices

    def screen_rep(self):
        print("CISCO DEVICES")
        print("IP Address\t"+"Connect status\t"+"Family\t"+"Model\t"+"Serial\t"+"IOS Version")
        while not cisco_dev_list.empty():
            cisco_dev = cisco_dev_list.get()
            print("Cisco {ip}: Connect status - {status}; IOS Version - {ios}".format(ip=cisco_dev.ip_address,
                                                                                      status=cisco_dev.status,
                                                                                      ios=cisco_dev.ios_ver))

    #def csv_rep(self):


class Inventor(threading.Thread):

    def __init__(self, thread_num, que, args):
        threading.Thread.__init__(self)
        self.thread_num = thread_num
        self.q = que
        self.args = args

    def run(self):
        print("Thread {0} started".format(self.thread_num))

        while not self.q.empty():
            ip_addr = self.q.get()
            response = self.port_check(ip_addr, self.args.port)
            if response:
                is_cisco = CiscoDevice(ip_addr, self.args.port)
                if is_cisco:
                    cisco_device = CiscoDevice(ip_addr, self.args.port)
                    cisco_device.inventory(self.args.user, self.args.secret)
                    cisco_dev_list.put(cisco_device)

        print("Thread {0} stoped".format(self.thread_num))

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


def main():

    # Argument parser
    parser = argparse.ArgumentParser(prog="CSPIT 1.0", description="Cisco SSH Python Inventory Tool")
    parser.add_argument("-t", "--target", action="store", required=True, help="IP address|range")
    parser.add_argument("-p", "--port", action="store", default=22, help="SSH port")
    parser.add_argument("-u", "--user", action="store", required=True, help="SSH User")
    parser.add_argument("-s", "--secret", action="store", required=True, help="SSH Password")
    args = parser.parse_args(sys.argv[1:])

    # Forming a queue of IP-addresses
    q = queue.Queue()
    target = ipaddress.IPv4Network(args.target)
    for ip_addr in target:
        ip_addr = str(ipaddress.IPv4Address(ip_addr))
        q.put(ip_addr)

    # Create, start and wait a threads
    thread_list = []
    for x in range(MAX_THREADS):
        thread = Inventor(x+1, q, args)
        thread_list.append(thread)
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()

    print("CISCO DEVICES")
    print("IP Address\t\t\t"+"Connect status\t\t\t"+"Family\t\t\t"+"Model\t\t\t"+"Serial\t\t\t"+"IOS Version")
    while not cisco_dev_list.empty():
        cisco_dev = cisco_dev_list.get()
        print("Cisco {ip}: Connect status - {status}; IOS Version - {ios}".format(ip=cisco_dev.ip_address,
                                                                                  status=cisco_dev.status,
                                                                                  ios=cisco_dev.ios_ver))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("/n")
        print("ERROR: Keyboard Interrupt")
        sys.exit(0)

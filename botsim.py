""" 
This data/work was created by employees of the National Institute of Standards and Technology (NIST), 
an agency of the Federal Government. Pursuant to title 17 United States Code Section 105, works of NIST 
employees are not subject to copyright protection in the United States.  This data/work may be subject to 
foreign copyright.
The data/work is provided by NIST as a public service and is expressly provided “AS IS.” 
NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED OR STATUTORY, INCLUDING, WITHOUT LIMITATION, 
THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. 
NIST does not warrant or make any representations regarding the use of the data or the results thereof, 
including but not limited to the correctness, accuracy, reliability or usefulness of the data. 
NIST SHALL NOT BE LIABLE AND YOU HEREBY RELEASE NIST FROM LIABILITY FOR ANY INDIRECT, CONSEQUENTIAL, SPECIAL, 
OR INCIDENTAL DAMAGES (INCLUDING DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF 
BUSINESS INFORMATION, AND THE LIKE), WHETHER ARISING IN TORT, CONTRACT, OR OTHERWISE, ARISING FROM OR 
RELATING TO THE DATA (OR THE USE OF OR INABILITY TO USE THIS DATA), EVEN IF NIST HAS BEEN ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGES.
To the extent that NIST may hold copyright in countries other than the United States, you are hereby granted 
the non-exclusive irrevocable and unconditional right to print, publish, prepare derivative works and 
distribute the NIST data, in any medium, or authorize others to do so on your behalf, on a royalty-free 
basis throughout the world.
You may improve, modify, and create derivative works of the data or any portion of the data, and you may 
copy and distribute such modifications or works. Modified works should carry a notice stating that you changed 
the data and should note the date and nature of any such change. Please explicitly acknowledge the 
National Institute of Standards and Technology as the source of the data:  
Data citation recommendations are provided at https://www.nist.gov/open/license.
Permission to use this data is contingent upon your acceptance of the terms of this agreement and upon your 
providing appropriate acknowledgments of NIST’s creation of the data/work.
See: https://www.nist.gov/disclaimer
"""

#!/usr/bin/env python3
ver_str = 'Ver. 10/23/2019'

import sys
import argparse
import datetime as dt
import pandas as pd
from datetime import timedelta
from time import sleep
from statistics import mean, stdev
from random import randint, getrandbits, choice, choices, normalvariate
from ipaddress import IPv4Address, IPv4Network

"""
BotSim simulates bot activities in an enterprise network and produces
netflow like information of each activity with consideration of
weekday, work time and time difference.

written by mitsuhiro.hatada@nist.gov
"""


def thinking():
    # intervel between previous action and next action by botmaster
    # https://ci.nii.ac.jp/naid/170000181211/en/
    dt_cases = [50, 34, 91, 25, # Case d18
                5, 6, 11, 5, 7, 22, 27, 1, 14, # Case d33
                11, 10, 7, # Case d19
                7, 6, 17, 1, 2, 3, # Case d37
                25, # Case 11
                9, 28, 13, 30, 6, # Case 21
                205, 9, # Case e04
                10, 9, 9, 10, 2, 1, # Case f03
                6, 27, 22, 4, 7, 2, 27, # Case g14
                18, 19, 3, 19] # Case g15
    dt_min = min(dt_cases)
    dt_max = max(dt_cases)
    dt_mean = mean(dt_cases)
    dt_std = stdev(dt_cases)
    while True:
        tmp = normalvariate(dt_mean, dt_std)
        if dt_min < tmp and tmp < dt_max:
            break

    ttime = tmp * 60 * 1000000 # minutes to microseconds

    return(ttime)


def exfiltrate(event, target, network, c2, next_targets, src_port_to_c2, work_start, work_end, interval, time_diff, max_overwork):
    """
    This is intended to exfiltrate a file without privilege escalation.
    If privilege escalation is needed, some additional attacks should be considered.
    This is not emulated each protocol completely to communicate with hosts.
    """
    src_addr = target

    if len(next_targets) > 0:
        for next_target in choices(next_targets, k=randint(0, len(next_targets))): # 0: local file
            while True:
                if check_active(event, work_start, work_end) is True:

                    type = choice(["in", "out"])
                    if type == "in":
                        sIP = c2.split(':')[0]
                        dIP = target
                        sPort = int(c2.split(':')[1])
                        dPort = randint(49152, 65535)
                        flags = ' S  A   '
                        src_port_to_c2 = dPort
                    else:
                        sIP = target
                        dIP = c2.split(':')[0]
                        sPort = randint(49152, 65535)
                        dPort = int(c2.split(':')[1])
                        flags = ' S      '
                        src_port_to_c2 = sPort
                    bytes = randint(92, 300000)
                    packets = randint(1, int(bytes / 1460) + 1)
                    sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
                    dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
                    duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
                    print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[c2] keepalive"))
                    event = event + dt_duration

                    if check_active((event + dt.timedelta(hours=time_diff)), work_start, work_end + randint(0, max_overwork)) is True:
                        src_port_to_c2 = randint(49152, 65535)
                        break
                event = event + dt.timedelta(seconds=interval)

            type = choice(["in", "out"])
            if type == "in":
                sIP = next_target[0]
                dIP = target
                sPort = next_target[1]
                dPort = randint(49152, 65535)
                flags = ' S  A   '
            else:
                sIP = target
                dIP = next_target[0]
                sPort = randint(49152, 65535)
                dPort = next_target[1]
                flags = ' S      '
            bytes = randint(5000, 256000)
            packets = randint(1, int(bytes / 1460) + 1)
            sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
            dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
            duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
            # Internal communication
            #print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[exfitration] search remote files"))
            event = event + dt_duration

            # thinking about next action
            event = event + dt.timedelta(microseconds=thinking())

            if randint(0, 10) == 0: # file discovered
                break

    type = choice(["in", "out"])
    if type == "in":
        sIP = c2.split(':')[0]
        dIP = target
        sPort = int(c2.split(':')[1])
        dPort = src_port_to_c2
        flags = ' S  A   '
    else:
        sIP = target
        dIP = c2.split(':')[0]
        sPort = src_port_to_c2
        dPort = int(c2.split(':')[1])
        flags = ' S      '
    bytes = randint(5000, 256000)
    packets = randint(1, int(bytes / 1460) + 1)
    sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
    dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
    duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
    print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[c2] send file"))
    event = event + dt_duration

    return(event)


def scan(event, target, network, c2, src_port_to_c2):
    """
    Threre are many varieties for scannning. Here, this executes
    1) ping, 2) scan specific ports on multiple hosts
    """
    with open('./active_hosts.txt') as f:
        hosts = f.read().splitlines()

    next_targets = []

    # ping
    dst_addrs = choices(hosts, k=randint(0, 5)) # 0: no ping
    for dst_addr in dst_addrs:

        type = choice(["in", "out"])
        if type == "in":
            sIP = dst_addr
            dIP = target
        else:
            sIP = target
            dIP = dst_addr
        bytes = 76
        packets = 1
        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
        dt_duration = dt.timedelta(microseconds=randint(2000, 5000))
        duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
        flags = '        '
        # Internal communication
        #print("%s|%d|%s|%s|||%d|%d|%s|%s|%s|%s" % (type, 1, sIP, dIP, packets, bytes, sTime, duration, flags, "[scan] ping"))
        event = event + dt_duration

        if randint(0, 1) == 0: # random choice of response
            event = event + dt.timedelta(microseconds=randint(50000, 100000))

    if len(dst_addrs) > 0:
        type = choice(["in", "out"])
        if type == "in":
            sIP = c2.split(':')[0]
            dIP = target
            sPort = int(c2.split(':')[1])
            dPort = src_port_to_c2
            flags = ' S  A   '
            src_port_to_c2 = dPort
        else:
            sIP = target
            dIP = c2.split(':')[0]
            sPort = src_port_to_c2
            dPort = int(c2.split(':')[1])
            flags = ' S      '
        bytes = randint(1500, 300000)
        packets = randint(1, int(bytes / 1460) + 1)
        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
        dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
        duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
        print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[c2] send result of ping"))
        event = event + dt_duration

        # thinking about next action
        event = event + dt.timedelta(microseconds=thinking())

    # port scan
    dst_addrs = choices(hosts, k=randint(0, int(len(hosts) / 2))) # 0: no scan
    dst_ports = choices([21, 443, 445, 3389], k=randint(1, 4))
    for dst_addr in dst_addrs:
        for dst_port in dst_ports:
            type = choice(["in", "out"])
            if type == "in":
                sIP = dst_addr
                dIP = target
                sPort = dst_port
                dPort = randint(49152, 65535)
                flags = ' S  A   '
            else:
                sIP = target
                dIP = dst_addr
                sPort = randint(49152, 65535)
                dPort = dst_port
                flags = ' S      '
            bytes = randint(100, 256)
            packets = 1
            sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
            dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
            duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
            # Internal communication
            #print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[scan] port scan"))
            event = event + dt_duration

            if randint(0, 5) == 0: # random choice of response
                event = event + dt.timedelta(microseconds=randint(2000, 5000))
                next_targets.append([dst_addr, dst_port])

    if len(dst_addrs) > 0:
        type = choice(["in", "out"])
        if type == "in":
            sIP = c2.split(':')[0]
            dIP = target
            sPort = int(c2.split(':')[1])
            dPort = src_port_to_c2
            flags = ' S  A   '
        else:
            sIP = target
            dIP = c2.split(':')[0]
            sPort = src_port_to_c2
            dPort = int(c2.split(':')[1])
            flags = ' S      '
        bytes = randint(1500, 300000)
        packets = randint(1, int(bytes / 1460) + 1)
        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
        dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
        duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
        print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[c2] send result of scan"))
        event = event + dt_duration

    # thinking about next action
    event = event + dt.timedelta(microseconds=thinking())

    return(event, next_targets)


def net_cmd(event, target, network):
    """
    Since this hardly emulates the netbios protocols,
    this might be considered multiple ports use and responses.
    """
    # netbios-dgm
    for n in range(0, randint(1, 3)):
        type = choice(["in", "out"])
        if type == "in":
            sIP = IPv4Network(network).broadcast_address
            dIP = target
            sPort = 138
            dPort = 138
        else:
            sIP = target
            dIP = IPv4Network(network).broadcast_address
            sPort = 138
            dPort = 138
        bytes = randint(1500, 300000)
        packets = randint(1, int(bytes / 1460) + 1)
        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
        dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
        duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
        flags = '        '
        # Internal communication
        #print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 17, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[info gathering] netbios command"))
        event = event + dt_duration

        event = event + dt.timedelta(microseconds=randint(400, 1000))

        # netbios-ns
        for m in range(0, randint(2, 5)):
            type = choice(["in", "out"])
            if type == "in":
                sIP = IPv4Network(network).broadcast_address - 1 # gateway
                dIP = target
                sPort = 137
                dPort = 137
            else:
                sIP = target
                dIP = IPv4Network(network).broadcast_address - 1 # gateway
                sPort = 137
                dPort = 137
            bytes = randint(1500, 300000)
            packets = randint(1, int(bytes / 1460) + 1)
            sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
            dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
            duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
            flags = '        '
            # Internal communication
            #print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 17, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[info gathering] netbios command"))
            event = event + dt_duration

            # thinking about next action
            event = event + dt.timedelta(microseconds=thinking())

    return(event)


def get_info(event, target, network, c2, src_port_to_c2):
    """
    typical commands:
        "tasklist", "systeminfo", "netstat", "ipconfig", "dir", "net view/user/group"
    """
    for n in range(0, randint(1, 5)):
        type = choice(["in", "out"])
        if type == "in":
            sIP = c2.split(':')[0]
            dIP = target
            sPort = int(c2.split(':')[1])
            dPort = src_port_to_c2
            flags = ' S  A   '
        else:
            sIP = target
            dIP = c2.split(':')[0]
            sPort = src_port_to_c2
            dPort = int(c2.split(':')[1])
            flags = ' S      '
        bytes = randint(1500, 300000)
        packets = randint(1, int(bytes / 1460) + 1)
        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
        dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
        duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
        print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[c2] send host information"))
        event = event + dt_duration

        # thinking about next action
        event = event + dt.timedelta(microseconds=thinking())

    # "net"
    event = net_cmd(event, target, network)
    sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
    print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[c2] send host information"))

    # thinking about next action
    event = event + dt.timedelta(microseconds=thinking())

    return(event)


def c2_control(start, target, network, c2, interval, time_diff, work_start, work_end, max_overwork, level, limit):
    event = start
    #active = dt.timedelta(seconds=randint(3600, 86400))
    progress = 0

    # keepalive
    while True:
        # give up
        if event > start + dt.timedelta(days=limit):
            print(event.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3], "[Done] gave up...orz", file=sys.stderr)
            sys.exit()

        # host active time
        if check_active(event, work_start, work_end) is False:
            event = event + dt.timedelta(seconds=interval)
            continue

        # ping / pong
        type = choice(["in", "out"])
        if type == "in":
            sIP = c2.split(':')[0]
            dIP = target
            sPort = int(c2.split(':')[1])
            dPort = randint(49152, 65535)
            flags = ' S  A   '
            src_port_to_c2 = dPort
        else:
            sIP = target
            dIP = c2.split(':')[0]
            sPort = randint(49152, 65535)
            dPort = int(c2.split(':')[1])
            flags = ' S      '
            src_port_to_c2 = sPort
        bytes = randint(92, 1460)
        packets = 5
        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
        dt_duration = dt.timedelta(microseconds=randint(10000, 500000))
        duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
        print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[c2] keepalive"))
        event = event + dt_duration

        if choices([True, False], weights = [20, 1])[0]:
            event = event + dt.timedelta(seconds=interval)
            continue

        if level <= progress:
            print(event.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3], "[Done] attack level:", level, file=sys.stderr)
            sys.exit()

        ### thinking about next action
        event = event + dt.timedelta(microseconds=thinking())

        # control
        #if (event - start) < active:
        #    event = event + dt.timedelta(seconds=interval)
        #    continue
        #else:
        if 1 == 1:
            # botmaster active time with over time working
            if check_active((event + dt.timedelta(hours=time_diff)), work_start, work_end + randint(0, max_overwork)) is False:
                event = event + dt.timedelta(seconds=interval)
                continue

            ## infromation gathering
            if progress == 0:
                event = get_info(event, target, network, c2, src_port_to_c2)
                progress += 1
                continue
            ## scan
            if progress == 1:
                event, next_targets = scan(event, target, network, c2, src_port_to_c2)
                progress += 1
                continue
            ## exfiltration
            if progress == 2:
                event = exfiltrate(event, target, network, c2, next_targets, src_port_to_c2, work_start, work_end, interval, time_diff, max_overwork)
                progress += 1
                continue

    return(0)


def check_active(event, start, end):
    work_start = dt.datetime.combine(event.date(), dt.datetime.min.time()) + dt.timedelta(hours=start)
    work_end = dt.datetime.combine(event.date(), dt.datetime.min.time()) + dt.timedelta(hours=end)
    if event.weekday() in range(0, 5):
        if work_start <= event <= work_end:
            return(True)
        else:
            return(False)
    else:
        return(False)


def init_infection(event, trigger, sequence, target, dns, work_start, work_end):
    # host active time
    if check_active(event, work_start, work_end) is False:
        print("%s [Error] Host is not working" % event.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3], file=sys.stderr)
        sys.exit()

    # general drive-by sequence: 1) landing, 2) exploit, and 3) download
    ## multiple sessisons observe for getting contents when accessing a compromised web site including legitimate contents
    for n in range(0, sequence * randint(3, 10)):
        # DNS query/response
        '''
        type = choice(["in", "out"])
        if type == "in":
            sIP = dns.split(':')[0]
            dIP = target
            sPort = int(dns.split(':')[1])
            dPort = randint(49152, 65535)
        else:
            sIP = target
            dIP = dns.split(':')[0]
            sPort = randint(49152, 65535)
            dPort = int(dns.split(':')[1])
        bytes = randint(92, 1460)
        packets = 1
        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
        dt_duration = dt.timedelta(microseconds=randint(5000, 10000))
        duration = str(dt_duration.seconds) + '.' + str(dt_duration.microseconds)[:-2]
        flags = '        '
        print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 17, sIP, dIP, sPort, dPort, packets, bytes, sTime, duration, flags, "[infection] dns query/response for web access"))
        event = event + dt_duration
        '''

        event = event + dt.timedelta(microseconds=randint(10000, 20000))

        # HTTP request/response
        ## weights are the number of flows at port 80 in the benign data
        type = choices(["in", "out"], weights = [20254030, 23740686])[0]
        if type == "in":
            sIP = str(IPv4Address(getrandbits(32)))
            dIP = target
            sPort = choice([80, 443])
            dPort = randint(49152, 65535)
            flags = ' S  A   '
        else:
            sIP = target
            dIP = str(IPv4Address(getrandbits(32)))
            sPort = randint(49152, 65535)
            dPort = choice([80, 443])
            flags = ' S      '

        # bytes, packets and duration based on statistics of benign traffic
        df_stats = pd.read_pickle('./stats.pickle')
        while True:
            tmp = normalvariate(df_stats['bytes']['mean'], df_stats['bytes']['std'])
            if df_stats['bytes']['min'] < tmp and tmp < df_stats['bytes']['max']:
                bytes = int(tmp)
                break

        packets = int(df_stats['packets']['mean'] * (bytes / df_stats['bytes']['mean']))

        duration = df_stats['duration']['mean'] * (bytes / df_stats['bytes']['mean'])

        sTime = event.strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]

        if trigger == 1:
            message = "[infection] http get request/response for downloading bot"
        else:
            message = "[infection] http get request/response for drive-by attack"
        print("%s|%d|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s" % (type, 6, sIP, dIP, sPort, dPort, packets, bytes, sTime, '{:.4f}'.format(duration), flags, message))

        # In case of infection by e-mail attachement, a dropper download a main bot program.
        if trigger == 1:
            break

    event = event + dt.timedelta(seconds=duration)

    return(event)


def main():
    # Major Parameters
    init_def = (dt.datetime.now() - timedelta(days=7)).strftime("%Y/%m/%dT%H:%M:%S.%f")[:-3]
    parser = argparse.ArgumentParser(description="Generate netflow log for botnet activities.")
    parser.add_argument('-s', dest='work_start', type=int, choices=list(range(0, 10)), default=8,
                        help='time to start working [0...10] (default: 8)')
    parser.add_argument('-e', dest='work_end', type=int, choices=list(range(15, 24)), default=21,
                        help='time to go home [14...24] > work_start (default: 21)')
    parser.add_argument('-i', dest='init_time', type=str, default=init_def,
                        help='date time of initial infection [%%Y/%%m/%%dT%%H:%%M:%%S.%%f] (default: 7 days ago)')
    parser.add_argument('-a', dest='init_trigger', type=int, choices=list(range(0,2)), default=0,
                        help='attack trigger of initial infection [0: phishing, 1: e-mail attachement] (default: 0)')
    parser.add_argument('-t', dest='init_target_host', type=str, default='192.168.0.104',
                        help='target host of initial infection [IPv4 Address] (default: 192.168.0.104)')
    parser.add_argument('-n', dest='init_target_nw', type=str, default='192.168.0.0/24',
                        help='target network of initial infection [IPv4 Network] (default: 192.168.0.0/24)')
    parser.add_argument('-l', dest='attack_level', type=int, choices=list(range(0,4)), default=3,
                        help='attack level [0: infection, 1: host information gathering, 2: scanning, 3: exfitration] (default: 3)')
    parser.add_argument('-c', dest='c2_host', type=str, default='67.202.92.14:80',
                        help='c2 [IPv4 Address:Port] (default: 67.202.92.14:80)')
    parser.add_argument('-k', dest='c2_interval', type=int, default=3600,
                        help='interval for keepalive with c2 [Seconds] (default: 3600)')
    parser.add_argument('-d', dest='botmaster_td', type=int, default=0,
                        help='time difference to botmaster location [Hours] (default: 0)')
    parser.add_argument('-o', dest='max_overwork', type=int, default=8,
                        help='maximum overtime work for botmaster [Hours] (default: 8)')
    parser.add_argument('-m', dest='limit_days', type=int, default=randint(30, 90),
                        help='maximum number of days to keep attacking [Days] (default: randint(30, 90))')
    parser.add_argument('-v', '--version', action='version', version=ver_str)

    args = parser.parse_args()
    ## General (target and botmaster)
    work_start = args.work_start
    work_end = args.work_end
    ## Target Environment
    ns_host = '192.168.0.254:53'
    ## Initial infection
    init_time = dt.datetime.strptime(args.init_time, '%Y/%m/%dT%H:%M:%S.%f')
    init_trigger = args.init_trigger
    driveby_seq = randint(2, 5)
    init_target_host = args.init_target_host
    init_target_nw = args.init_target_nw
    attack_level = args.attack_level
    ## C2
    c2_host = args.c2_host
    c2_interval = args.c2_interval
    botmaster_td = args.botmaster_td
    max_overwork = args.max_overwork
    limit_days = args.limit_days

    # Activities
    print("%s [Start] find an intersting file?" % init_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3], file=sys.stderr)

    print('type|protocol|sIP|dIP|sPort|dPort|packets|bytes|sTime|duration|initialTCPflags|activity')
    event = init_infection(init_time, init_trigger, driveby_seq, init_target_host, ns_host, work_start, work_end)

    c2_control(event, init_target_host, init_target_nw, c2_host, c2_interval, botmaster_td, work_start, work_end, max_overwork, attack_level, limit_days)


if __name__ == '__main__':
    main()

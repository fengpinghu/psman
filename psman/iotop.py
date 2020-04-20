# -*- coding: utf-8 -*-
""" iotop Collects disk io data per process.

It uses the iotop python program, a top-like utility for displaying
real-time disk activity.

    Typical usage example:
    start()
    wait()
    access the data in the list procs

"""

import subprocess
import threading
import re

procs = []
_monitor_thread = None

def get_pstable(t):
    global procs
    process = subprocess.Popen(
        ['iotop', '-n', '2', '-o', '-b', '-d', str(t), '-P', '-k', '-qqq'],
        stdout=subprocess.PIPE)
    for ps in process.stdout.readlines():
        ps = ps.strip()
        #print (ps)
        ps_a = [x.strip() for x in re.sub(r'\s+', ' ', ps).split(' ', 11)]
        #print (ps_a)
        (ps_pid, ps_prio, ps_user, ps_read, _, ps_write,
         _, _, _, _, _, ps_comm) = tuple(ps_a)
        procs.append({'pid': ps_pid,
                      'user': ps_user,
                      'read_kbs': ps_read,
                      'write_kbs': ps_write,
                      'ps_comm': ps_comm
                     })
    #remove duplicates
    procs = {i['pid']:i for i in procs}.values()


def start(t=2):
    """ start the data collection thread
    """
    global _monitor_thread
    _monitor_thread = threading.Thread(
        target=get_pstable, args=(t,))
    _monitor_thread.start()

def wait():
    """ wait for the data collection thread to finish
    """
    done = False
    while not done:
        _monitor_thread.join(0.3)
        done = not _monitor_thread.is_alive()

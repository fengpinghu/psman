"""check user process on the worker node.

"""

import sys
import logging
import os
import psutil
import shlex, subprocess
from utils import sys_cmd

_logger = logging.getLogger(__name__)

def find_procs_by_name(name):
    "Return a list of processes matching 'name'."
    ls = []
    for p in psutil.process_iter(["name", "exe", "cmdline"]):
        if name == p.info['name'] or \
                p.info['exe'] and os.path.basename(p.info['exe']) == name or \
                p.info['cmdline'] and p.info['cmdline'][0] == name:
            ls.append(p)
    return ls


def psman_run(args, cfg):
    _logger.debug("Starting psman...")

    ps = find_procs_by_name("abc")
    for p in ps:
        print (p.pid)

    #fail, out, err = _sys_cmd("squeue --Format=jobid,tres:50 -w c0301")
    fail, out, err = sys_cmd("hostname")
    
    _logger.info(out)
    #print(out)

    _logger.debug("psman run done")


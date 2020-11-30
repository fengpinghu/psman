"""check user process on the worker node.

"""

import sys
import logging
import os
import psutil
import shlex, subprocess
import re
from utils import sys_cmd
from psman.byteshuman import human2bytes, bytes2human


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

jobs={}

def psman_run(args, cfg):
    _logger.debug("Starting psman...")

    ps = find_procs_by_name("abc")
    for p in ps:
        print (p.pid)
    # where am I running at
    (sysname, nodename, release, version, machine) = os.uname()
    nodename = nodename.split('.', 1)[0] 
    fail, out, err = sys_cmd("squeue --Format=UserName,jobid,tres:50 -h -w {}".format(nodename))
    #fail, out, err = sys_cmd("scontrol listpids")
    _logger.debug("squeue --Format=UserName,jobid,tres:50 -h -w {}".format(nodename))
    for job in out.splitlines():
       _logger.debug(job)
       user, job_id, tres = [x.strip() for x in re.sub(r'\s+', ' ', job).split(' ', 2)]
        
       tres = dict((k, human2bytes(v)) if k=="mem" else (k, int(v))  
                   for k,v in (t.split('=') for t in tres.split(',')))
       jobs[job_id] = {"user": user,
                       "tres": tres,
                       "procs":[],
                       "res": {"threads": 0,
                               "rss": 0
                              }
                      }
       #print (":",job)

    #print(jobs)
    fail, out, err = sys_cmd("scontrol listpids")
    lines = out.splitlines()
    if lines:
        lines = lines[1:]
    _logger.debug("scontrol listpids")
    for job in lines:
       _logger.debug(job)
       pid, job_id, _ = [x.strip() for x in re.sub(r'\s+', ' ', job).split(' ', 2)]
       #print (":",job)
       pid = int(pid)
       if pid == -1:
           continue
       jobs[job_id]["procs"].append(pid)
        
       p = psutil.Process(pid=int(pid))
       procs = p.children(recursive=True)
       procs.append(p)
       for p in procs:
           with p.oneshot():
               jobs[job_id]["res"]["threads"] += p.num_threads()
               #mem = p.memory_info()
               #print(mem.rss)
               jobs[job_id]["res"]["rss"] += p.memory_info().rss
       
    #print(jobs)
    
    for job_id, job in jobs.items():
        if job['tres']['node'] > 1:
            _logger.info("job: {} by user: {} requested more than 1 node, skip resource checking")
            continue
        if job['res']['threads'] < job['tres']['cpu']:
            _logger.warn("job: {} by user: {} over requsted cpu, requested: {}, used: {}".format(
                job_id, job['user'], job['tres']['cpu'], job['res']['threads'])) 
        if job['res']['rss'] * 20 < job['tres']['mem']:
            _logger.warn("job: {} by user: {} over requsted mem(use less than 5%), requested: {}, used: {}".format(
                job_id, job['user'], bytes2human(job['tres']['mem']), bytes2human(job['res']['rss']))) 
    
    
    #_logger.info(out)

    _logger.debug("psman run done")


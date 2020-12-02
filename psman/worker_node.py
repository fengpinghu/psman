"""check user process on the worker node.

"""

import sys
import logging
import os
import psutil
import shlex, subprocess
import re
import time
import datetime

from file_read_backwards import FileReadBackwards
from psman.utils import sys_cmd, notification

from psman.byteshuman import human2bytes, bytes2human
from enum import IntFlag

class JobState(IntFlag):
    CPU_O = 4
    MEM_O = 2
    GPU_O = 1
    NONE = 0 

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

_jobs = {}

def psman_run(args, cfg):
    global _jobs
    jobs = {}
    found = {}
    _logger.debug("Starting psman...")

    ps = find_procs_by_name("abc")
    for p in ps:
        print (p.pid)

    actions = []
    now = int(time.time())
    # where am I running at
    (sysname, nodename, release, version, machine) = os.uname()
    nodename = nodename.split('.', 1)[0]
    cmd = "squeue --Format=UserName,jobid,tres:50 -h -w {}".format(nodename)
    fail, out, err = sys_cmd(cmd)
    #fail, out, err = sys_cmd("scontrol listpids")
    _logger.debug(cmd)
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
    #find all gpu processes
    gpu_procs = []
    cmd = "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv"
    fail, out, err = sys_cmd(cmd)
    lines = out.splitlines()
    if lines:
        lines = lines[1:]
    _logger.debug("nvidia-smi")
    for job in lines:
       pid, proc_name, mem = [x.strip() for x in re.sub(r'\s+', '', job).split(',', 2)]
       gpu_procs.append(pid)

    _logger.debug(gpu_procs)

    #print(jobs)
    cmd = "scontrol listpids"
    fail, out, err = sys_cmd(cmd)
    lines = out.splitlines()
    if lines:
        lines = lines[1:]
    _logger.debug(cmd)
    for job in lines:
       _logger.debug(job)
       pid, job_id, _ = [x.strip() for x in re.sub(r'\s+', ' ', job).split(' ', 2)]
       #print (":",job)
       pid = int(pid)
       if pid == -1:
           continue
       jobs[job_id]["procs"].append(pid)
       try: 
           p = psutil.Process(pid=int(pid))
           procs = p.children(recursive=True)
           child_pids = [p.pid for p in procs]
           jobs[job_id]["procs"].extend(child_pids)
    
           procs.append(p)
           for p in procs:
               with p.oneshot():
                   jobs[job_id]["res"]["threads"] += p.num_threads()
                   #mem = p.memory_info()
                   #print(mem.rss)
                   jobs[job_id]["res"]["rss"] += p.memory_info().rss
       except Exception as e:
           _logger.warn("skip iteration due to exception: %s", e)
           return
    #print(jobs)
    
    for job_id, job in jobs.items():
        if job['tres']['node'] > 1:
            _logger.info("job: {} by user: {} requested more than 1 node, skip resource checking")
            continue
        if job['res']['threads'] < job['tres']['cpu']:
            _logger.warn("job: {} by user: {} over requsted cpu, requested: {}, used: {}".format(
                job_id, job['user'], job['tres']['cpu'], job['res']['threads']))
            found[job_id] = found.get(job_id, JobState.NONE) | JobState.CPU_O
        if job['res']['rss'] * 20 < job['tres']['mem']:
            _logger.warn("job: {} by user: {} over requsted mem(use less than 5%), requested: {}, used: {}".format(
                job_id, job['user'], bytes2human(job['tres']['mem']), bytes2human(job['res']['rss']))) 
            found[job_id] = found.get(job_id, JobState.NONE) | JobState.MEM_O
        if job['tres'].get('gres/gpu'):
            if set(job['procs']) & set(gpu_procs):  
                _logger.warn("job: {} by user: {} not using the requested GPU, requested: {}, used: {}".format(
                    job_id, job['user'],job['tres'].get('gres/gpu'), 0)) 
                found[job_id] = found.get(job_id, JobState.NONE) | JobState.GPU_O

    #print (found)
    # clean up
    #for jid, job in _jobs.items():
    for jid in list(_jobs):
        if jid not in found.keys():
            del _jobs[jid]

    #_logger.info(out)
    for jid, state in found.items():
        if not _jobs.get(jid):
            _jobs[jid] = {'state': JobState.NONE}
        job = _jobs[jid]
    #for jid, job in _jobs.items():
        #comments="""
        if job['state'] & state & JobState.CPU_O:
            _logger.warn("job: {} by user: {} over requsted cpu since {}".format(
                           jid, jobs[jid]['user'], job['CPU_start_time']))
            if now - job['CPU_start_time'] > args.elps:
                actions.append({'action': 'notification',
                                'job_id': jid,
                                #'comm': ps_comm,
                                'user': jobs[jid]['user'],
                                'reason': 'cpu'})
        elif state & JobState.CPU_O:
            job['state'] = job.get('state', JobState.NONE) | JobState.CPU_O 
            job['CPU_start_time'] = now
        elif job['state'] & JobState.CPU_O:
            job['state'] = job['state'] - JobState.CPU_O

        if job['state'] & state & JobState.MEM_O:
            _logger.warn("job: {} by user: {} over requsted mem since {}".format(jid, jobs[jid]['user'], job['MEM_start_time']))
            if now - job['MEM_start_time'] > args.elps:
                actions.append({'action': 'notification',
                                'job_id': jid,
                                #'comm': ps_comm,
                                'user': jobs[jid]['user'],
                                'reason': 'mem'})
        elif state & JobState.MEM_O:
            job['state'] = job.get('state', JobState.NONE) | JobState.MEM_O 
            job['MEM_start_time'] = now
        elif job['state'] & JobState.MEM_O:
            job['state'] = job['state'] - JobState.MEM_O

        if job['state'] & state & JobState.GPU_O:
            _logger.warn("job: {} by user: {} requsted gpu but not using since {}".format(jid, jobs[jid]['user'], job['GPU_start_time']))
            if now - job['GPU_start_time'] > args.elps:
                actions.append({'action': 'notification',
                                'job_id': jid,
                                #'comm': ps_comm,
                                'user': jobs[jid]['user'],
                                'reason': 'gpu'})
        elif state & JobState.GPU_O:
            job['state'] = job.get('state', JobState.NONE) | JobState.GPU_O 
            job['GPU_start_time'] = now
        elif job['state'] & JobState.GPU_O:
            job['state'] = job['state'] - JobState.GPU_O
        #"""
    #print (_jobs)
    for action in actions:
        if action['action'] == 'notification':
            if not _notification_sent(cfg['logfile'], action['user'], action['job_id'],
                                      action['reason'], now, 3600):
                _logger.warning("Internal Notification sent - User: %s, job_id: %s, " \
                             "reason: %s", action['user'], action['job_id'], action['reason'])
                msg = "job: {} by user: {} over requested: {}, time elapsed: {} seconds" \
                      "(sampled at {} seconds interval)".format(
                        action['user'], action['job_id'], action['reason'], args.elps, args.daemon
                        )
                notification(msg,
                             To=cfg['msg_cc'],
                             From=cfg['msg_from'],
                             Cc=[],
                             subj=cfg['msg_subj'],
                             smtpHost=cfg['smtpHost'])

    _logger.debug("psman run done")

def _notification_sent(logfile, user, job_id, reason, now, secs):

    prog_t = re.compile(r'^\[(.*),.*\] .*')
    line = "Internal Notification sent - User: {}, job_id: {}, " \
                    "reason: {}".format(user, job_id, reason)
    prog_n = re.compile(re.escape(line))
    ret = False
    with FileReadBackwards(logfile, encoding="utf-8") as frb:
        for l in frb:
            result = prog_t.match(l)
            if result:
                t = time.mktime(datetime.datetime.strptime(
                              result.group(1), "%Y-%m-%d %H:%M:%S").timetuple())
                if t < now - secs:
                    break
            result = prog_n.search(l)
            if result:
                ret = True
    return ret



import subprocess
import re
import shlex
import logging


procs=[]

pstable_raw={}

# only user processes
pstable = {}

# user processses with exempted process excluded
pstable_e = {}

UID,PID,PPID,PGID,RSS,CPUTIME,COMM=range(7)

_logger = logging.getLogger(__name__)

def kill_process(pstable, pid):
    """kill the process """
    (ps_uid,ps_pid,ps_ppid,ps_pgid,ps_rss,ps_time,ps_comm)=tuple(pstable[pid])
    # if the process group id is also in the pstable, ok to kill
    # otherwise just try the pid
    # return the pid/pgid if processes are killed , otherwiese return False
    pidtokill = pid
    killpg = False
    if ps_pgid in pstable.keys():
        killpg=True
        pidtokill= ps_pgid
        cputime_total= sum ( v[5] for k,v in pstable.iteritems() if v[3] == ps_pgid  )
    else:
        cputime_total = ps_time

    ret = pidtokill

    #try:
    #    if killpg:
    #        os.killpg(int(pidtokill),signal.SIGKILL)
    #    else:
    #        os.kill(int(pidtokill),signal.SIGKILL)
    #except:
    #    logging.info("failed to kill -- p(g)id:%s",pidtokill)
    #    ret= False

    if ret != False:
        _logger.info("hogging process killed -- pid:%s",pidtokill)
    return ret, cputime_total

def walktoRoot( pstable,exemptParentProcess, pid ):
    """recursively check if parent process is ok"""

    (ps_uid,ps_pid,ps_ppid,ps_pgid,ps_rss,ps_time,ps_comm)=tuple(pstable[pid])

    #logging.debug("pid:%s,parent:%s,program:%s",ps_pid,ps_ppid,ps_comm)

    #reaching to the end
    if( int(ps_ppid) < 2 ):
      #logging.debug("reaching to the root")
      return 0
    elif(ps_comm in exemptParentProcess):
      #logging.debug("%s is in the exempt list",ps_comm)
      return 1
    else:
      ret=walktoRoot(pstable,exemptParentProcess,ps_ppid)
      return ret

def is_exempted_ps( pstable, exeps, exeps_parent, pid):
    exempted = False
    (ps_uid,ps_pid,ps_ppid,ps_pgid,ps_rss,ps_time,ps_comm)=tuple(pstable[pid])
    if ps_comm in exeps:
        exempted = True
    elif walktoRoot(pstable, exeps_parent,pid):
        exempted = True
    return exempted

def is_ldap_user(n,t='passwd'):
    """check if a user or group is from ldap """

    cmd="getent --service=sss "+t+" "+ n
    args=shlex.split(cmd)
    p=subprocess.Popen(args,stdout=subprocess.PIPE)
    p.communicate()
    return not p.returncode

def get_pstable( exemptUsers = [], exeps = [], exeps_parent = [] ):

    global procs
    global pstable_raw
    global pstable
    global pstable_e

    process = subprocess.Popen(
              ['ps','-eo',"user,pid,ppid,pgid,rss,time,comm"],
              stdout=subprocess.PIPE )
    for ps in process.stdout.readlines():

        ps_a = [ x.strip() for x in re.sub('\s+',' ',ps).split(' ',6) ]
        (ps_uid,ps_pid,ps_ppid,ps_pgid,ps_rss,ps_time,ps_comm) = tuple( ps_a )

        if ps_pid == 'PID':
            continue

        pstable_raw[ps_pid] = ps_a

        # calculate cumulative cpu time in seconds "[dd-]hh:mm:ss"
        (run_hrs,run_mins,run_secs)=tuple(ps_time.split(':'))
        if re.search('-',run_hrs):
          (run_days_tmp,run_hrs_tmp)=tuple(run_hrs.split('-'))
          run_hrs=24*int(run_days_tmp) + int(run_hrs_tmp)
        ps_cpu_time= 3600 * int(run_hrs) + 60 * int(run_mins) + int(run_secs)
        pstable_raw[ps_pid][CPUTIME]=ps_cpu_time


    # keep only ldap users 
    pstable = { k:v  for (k,v) in pstable_raw.iteritems()
                 if (is_ldap_user(v[UID]) and
                     v[UID] not in exemptUsers )
               }
    # filter out exempted processes
    pstable_e = { k:v  for (k,v) in pstable.iteritems()
                 if not (is_exempted_ps(pstable_raw,exeps, exeps_parent, k)) 
               }



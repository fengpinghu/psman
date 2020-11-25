#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""check user process on the login node

"""

from __future__ import division, print_function, absolute_import

import sys
import logging
import time
import datetime
import os
import multiprocessing
import psutil
import re

from file_read_backwards import FileReadBackwards

from psman import __version__

from psman import netio
from psman import iotop
from psman import zabbix

from psman import byteshuman
from psman import utils
from psman import ps

_logger = logging.getLogger(__name__)

def psman_run(args, cfg):
    """psman steps
    """
    _logger.debug("Starting psman...")

    # set load threshold to cpu count if it's 0
    if cfg['loadavgthreshhold'] == 0:
        cfg['loadavgthreshhold'] = multiprocessing.cpu_count()
    # who are the exempted Users
    for g in cfg['exemptGroups']:
        #global exemptUsers
        m = utils.get_group_members(g)
        cfg['exemptUsers'] = cfg['exemptUsers']+m

    # sshd can't be exempted as a parent
    exemptParentProcess = [x for x in cfg['exemptProcess']
                           if x not in ["sshd", "emacs", "screen", "tmux"]]


    # where am I running at
    (sysname, nodename, release, version, machine) = os.uname()
    _logger.info("psman start on node: %s", nodename)

    #only support on linux for now
    if sysname != "Linux":
        _logger.error("only support Linux, not: %s", sysname)
        sys.exit(1)

    # What is my current loadaverage
    (load1, load5, load15) = os.getloadavg()
    # memory usage information
    mem = psutil.virtual_memory()


    _logger.info("load averages are: %s,%s,%s, loadthreshhold: %0.2f",
                 load1, load5, load15, cfg['loadavgthreshhold'])
    _logger.info("mem.available: %s, mem.total: %s, mem.threshold: %s",
                 byteshuman.bytes2human(mem.available),
                 byteshuman.bytes2human(mem.total),
                 byteshuman.bytes2human(eval(cfg['mem_threshold'])))
    actions = []
    #comments="""
    # start nethogs data collection thread
    now = int(time.time())
    if args.net:
        netio.start(args.n)
        iotop.start(args.n)
    
        t_from = now - args.z * 60
    
        z = zabbix.Zabbix(cfg['zabbix_url'],
                          cfg['zabbix_user'],
                          cfg['zabbix_pw'])
        hostid = z.get_hostidbyname(nodename)
    
        dev = cfg['nic_tocheck']
        # devio = {'dev': {'in': bps, 'out':bps} }
        devio = {}
        if hostid:
            for d in dev:
                devio[d] = {}
                for k in ['in', 'out']:
                    key = 'net.if.{}[{}]'.format(k, d)
                    itemid = z.getitemIDbyKey(key, hostid)
    
                    if itemid:
                        v = z.getitemHistoryAvg(itemid, hostid, t_from, now, history=3)
                        devio[d][k] = v
    
        if args.loglevel in [logging.DEBUG, logging.INFO]:
            #for k,v in devio.iteritems():
            for v in dev:
                d = devio.get(v)
                if d:
                    _logger.debug('{:<10} outgoing: {:>10}'.format(v,
                      byteshuman.bytes2human(d.get('out', 0),
                       "%(value).1f %(symbol)sbps")))
                    _logger.debug('{:<10} incoming: {:>10}'.format(v,
                      byteshuman.bytes2human(d.get('in', 0),
                       "%(value).1f %(symbol)sbps")))
    
    
        # wait for data collection to finish
        netio.wait(args.n)
        iotop.wait()
        #
        procs1 = netio.procs
        for d in dev:
            procs_d = [p for p in procs1 if p['dev'] == d]
            for i in ['sent_kbs', 'recv_kbs']:
                _logger.debug('-'*70)
                _logger.debug('top {} {}'.format(d, i))
                procs_sorted = sorted(procs_d,
                                      key=lambda k: float(k[i]),
                                      reverse=True)
                procs_sorted_keys = [p['pid'] for p in procs_sorted]
                procs_sorted_dupremoved = []
                for j in range(len(procs_sorted)):
                    if procs_sorted[j]['pid'] not in procs_sorted_keys[:j]:
                        procs_sorted_dupremoved.append(procs_sorted[j])
                value_map = {'recv_kbs': 'in', 'sent_kbs': 'out'}
                v = value_map[i]
                for p in procs_sorted_dupremoved[:3]:
                    if devio.get(d) and devio.get(d).get(v, 0) > eval(cfg['netio_threshold_dev']):
                        if ps.is_ldap_user(str(p['uid'])) and \
                           p[i]*1024*8 > eval(cfg['netio_threshold_ps']):
                            #print ('{},{}'.format( p['uid'], p[i]) )
                            actions.append({'action': 'internal_notification',
                                            'dev': d,
                                            'bw_dev': byteshuman.bytes2human( devio.get(d).get(v, 0),
                                                           "%(value).1f %(symbol)sbps"),
                                            'pid': p['pid'],
                                            'comm': p['name'],
                                            'user': utils.get_user_name(p['uid']),
                                            'bw_ps': byteshuman.bytes2human(
                                                         p[i]*1024*8,
                                                         "%(value).1f %(symbol)sbps"),
                                            'reason': v})
                    _logger.debug('{:<10}  {:<6}  {:>10}  {:<15}  {:<25}'.format(
                        'PID: ' + str(p['pid']),
                        'sent: ',
                        byteshuman.bytes2human(
                            p[i]*1024*8,
                            "%(value).1f %(symbol)sbps"),
                        'user: ' + utils.get_user_name(p['uid']),
                        'name: ' + p['name'][:25]))
    
        #
        #  process disk io data
        for i in ['read_kbs', 'write_kbs']:
            _logger.debug('-'*70)
            _logger.debug('top disk {}'.format(i))
            value_map = {'read_kbs': 'in', 'write_kbs': 'out'}
            #value_map1 = {'read_kbs': '', 'write_kbs': 'out'}
            value = value_map[i]
            exceeded = [v for k, v in devio.items() if v.get(value, 0) \
                        > eval(cfg['netio_threshold_dev'])]
            found = [a for a in actions if a['reason'] == value] 
            for j in sorted(iotop.procs,
                            key=lambda k: float(k[i]),
                            reverse=True)[:3]:
                if exceeded and not found:
                    if ps.is_ldap_user(str(j['user'])) and \
                       float(j[i])*1024*8 > eval(cfg['netio_threshold_ps']):
                        #print ('{},{}'.format( p['uid'], p[i]) )
                        actions.append({'action': 'internal_notification',
                                        'dev': 'disk',
                                        'bw_dev': byteshuman.bytes2human( exceeded[0].get(value, 0),
                                                       "%(value).1f %(symbol)sbps"),
                                        'pid': j['pid'],
                                        'comm': j['ps_comm'],
                                        'user': utils.get_user_name(j['user']),
                                        'bw_ps': byteshuman.bytes2human(
                                                     float(j[i])*1024*8,
                                                     "%(value).1f %(symbol)sbps"),
                                        'reason': value})
                _logger.debug('{:<10}  {:<6}  {:>10}  {:<15}  {:<25}'.format(
                    'PID: ' + str(j['pid']),
                    i,
                    byteshuman.bytes2human(
                        float(j[i])*1024*8,
                        "%(value).1f %(symbol)sbps"),
                    'user: ' + j['user'],
                    'name: ' + j['ps_comm'][:25]))
    
#"""
    #
    #  process pstable data
    ps.get_pstable(cfg['exemptUsers'],
                   cfg['exemptProcess'],
                   exemptParentProcess)
    actionlimit = cfg['killtop']
    hog_pids = []

    if args.loglevel in [logging.DEBUG, logging.INFO]:
        #if args.include:
        if False:
            table = ps.pstable
        else:
            table = ps.pstable_e
        _logger.debug('-'*70)
        _logger.debug('top cpu consumer:')
        for pid in sorted(table,
                          key=lambda k: table[k][ps.CPUTIME],
                          reverse=True)[:3]:
            (ps_uid, ps_pid, ps_ppid, ps_pgid, ps_rss, ps_time, ps_thc, ps_comm) = \
                       tuple(table[pid])
            _logger.debug('{:<10}  {:<6}  {:>10}  {:<15}  {:<25}'.format(
                'PID: ' + str(pid),
                'cputime: ',
                str(ps_time) + ' s',
                'user: ' + ps_uid,
                'name: ' + ps_comm))

        _logger.debug('-'*70)
        _logger.debug('top memory consumer:')
        for pid in sorted(table,
                          key=lambda k: int(table[k][ps.RSS]),
                          reverse=True)[:3]:
            (ps_uid, ps_pid, ps_ppid, ps_pgid, ps_rss, ps_time, ps_thc, ps_comm) = \
                       tuple(table[pid])
            _logger.debug('{:<10}  {:<6}  {:>10}  {:<15}  {:<25}'.format(
                'PID: ' + str(pid),
                'memory: ',
                byteshuman.bytes2human(int(ps_rss) * 1024),
                'user: ' + ps_uid,
                'name: ' + ps_comm))


    if float(load1) > float(cfg['loadavgthreshhold']):
        hog_pids = [v[ps.PID] for k, v in ps.pstable_e.items()
                    if v[ps.CPUTIME] > cfg['cputimelimit']]

    for pid in sorted(hog_pids,
                      key=lambda k: ps.pstable[k][ps.CPUTIME],
                      reverse=True):
        (ps_uid, ps_pid, ps_ppid, ps_pgid, ps_rss, ps_time, ps_thc, ps_comm) = \
                    tuple(ps.pstable[pid])
        _logger.info("hogging process found -- user: %s, cputime: %d, " \
                     "cmd: %s, pid: %s", ps_uid, ps_time, ps_comm, ps_pid)
        actions.append({'action': 'kill',
                        'pid': pid,
                        'comm': ps_comm,
                        'user': utils.get_user_firstname(ps_uid),
                        'reason': 'cpu'})
        if len(actions) >= actionlimit:
            break

    if True:
        if False:
            table = ps.pstable
        else:
            table = ps.pstable_e

        users = [v[ps.UID] for k, v in table.items()]
        users = list(set(users))
        user_cputs = [(u, sum([v[ps.CPUTIME] for k, v
                               in table.items() if v[ps.UID] == u]))
                      for u in users]
        user_procs = [(u,
                       sum([1 for k, v
                            in table.items() if v[ps.UID] == u]),
                       sum([int(v[ps.THCOUNT]) for k, v
                            in table.items() if v[ps.UID] == u])

                      ) for u in users]

        _logger.debug('-'*70)
        _logger.debug('top users in procs count:')
        # top 3 cpu  consumer
        for u in sorted(user_procs, key=lambda k: k[1], reverse=True)[:3]:
            _logger.debug('{:<15}  {:<9}  {:>10} '.format(
                'user: ' + u[0],
                'procs: ',
                str(u[1])))

        _logger.debug('-'*70)
        _logger.debug('top users in thread count:')
        # top 3 cpu  consumer
        for u in sorted(user_procs, key=lambda k: k[2], reverse=True)[:3]:
            _logger.debug('{:<15}  {:<9}  {:>10} '.format(
                'user: ' + u[0],
                'thread: ',
                str(u[2])))
            if u[2] > cfg['thc_threshhold']:
                actions.append({'action': 'internal_notification',
                                'user': u[0],
                                'procs': u[1],
                                'threads': u[2],
                                'reason': 'threadcount exceeded',
                                'pid': '-',
                                'comm': '-'})
                _logger.info("user runs many threads -- user: %s, procs: %d, " \
                             "threads: %d, limit: %d", u[0], u[1], u[2], cfg['thc_threshhold'])

        #print user_cputs
        _logger.debug('-'*70)
        _logger.debug('top users in cputime:')
        # top 3 cpu  consumer
        for u_t in sorted(user_cputs, key=lambda k: k[1], reverse=True)[:3]:
            #print (u_t)
            _logger.debug('{:<15}  {:<9}  {:>10} '.format(
                'user: ' + u_t[0],
                'cputime: ',
                str(u_t[1]) + ' s'))
            # only take actions against top users if systems is under load and
            # no individual hogging process is found
            if u_t[1] > cfg['cputimelimit_u'] and \
                (not hog_pids and float(load1) > float(cfg['loadavgthreshhold'])):
                pids = [k for k, v in ps.pstable_e.items() if v[ps.UID] == u_t[0]]
                # pick the top cpu cosumer for this user
                pid = sorted(pids,
                             key=lambda k: ps.pstable_e[k][ps.CPUTIME],
                             reverse=True)[0]
                (ps_uid, ps_pid, ps_ppid, ps_pgid, ps_rss, ps_time, ps_thc, ps_comm) = \
                        tuple(ps.pstable[pid])
                #_logger.info("top cpu comsumer -- user: %s, cputime: %d",
                #            u_t[0],u_t[1])

                _logger.info("hogging user found -- user: %s, total cputime %d, " \
                             "top cmd cputime: %d, cmd: %s, pid: %s",
                             ps_uid, u_t[1], ps_time, ps_comm, ps_pid)
                actions.append({'action': 'kill',
                                'pid': pid,
                                'comm': ps_comm,
                                'user': utils.get_user_firstname(ps_uid),
                                'reason': 'cpu'})

    pidstokill = []
    sortedpids = sorted(ps.pstable_e,
                        key=lambda k: int(ps.pstable[k][ps.RSS]),
                        reverse=True)

    if mem.available <= eval(cfg['mem_threshold']):
        pidstokill = sortedpids
    else:
        pidstokill = [p for p in sortedpids if
                      int(ps.pstable_e[p][ps.RSS])*1024 > eval(cfg['mem_threshold_p'])]

    for pid in pidstokill:
        (ps_uid, ps_pid, ps_ppid, ps_pgid, ps_rss, ps_time, ps_thc, ps_comm) = \
                tuple(ps.pstable[pid])
        _logger.info("hogging process found -- user: %s, memory: %d, " \
                     "cmd: %s, pid: %s", ps_uid,
                     byteshuman.bytes2human(int(ps_rss)*1024), ps_comm, ps_pid)
        actions.append({'action': 'kill',
                        'pid': pid,
                        'comm': ps_comm,
                        'user': utils.get_user_firstname(ps_uid),
                        'reason': 'mem'})
        if len(actions) >= actionlimit:
            break

    killedlist = []
    text_combined = ['', '']
    for action in actions:
        #print(action)
        if action['action'] == 'kill' and args.no_noop:
            pskilled, cputime_total = ps.kill_process(ps.pstable_e, action['pid'])
            # kill_process kills process group, so pskilled could be repeated
            # send notification only once if it's the case
            if pskilled and (pskilled not in killedlist):
                killedlist.append(pskilled)

                (ps_uid, ps_pid, ps_ppid, ps_pgid, ps_rss, ps_time, ps_thc, ps_comm) = \
                                        tuple(ps.pstable[pskilled])

                if action['reason'] == 'cpu':
                    text = cfg['msg'].format(
                        utils.get_user_firstname(ps_uid),
                        ps_comm,
                        nodename,
                        cputime_total,
                        cfg['loadavgthreshhold'],
                        cfg['cputimelimit'],
                        byteshuman.bytes2human(eval(cfg['mem_threshold'])))

                    text_internal = "process killed: {2}\nlogin node: {0}, " \
                                  "loadaverage: {1}, " \
                                  "process: {2}, pid: {3}, " \
                                  "user: {4}, cputime: {5}".format(
                                      nodename, load1, ps_comm,
                                      ps_pid, ps_uid, cputime_total)
                elif action['reason'] == 'mem':
                    text = cfg['msg_m'].format(
                        utils.get_user_firstname(ps_uid),
                        ps_comm,
                        nodename,
                        byteshuman.bytes2human(int(ps_rss)*1024),
                        cfg['loadavgthreshhold'],
                        cfg['cputimelimit'],
                        byteshuman.bytes2human(eval(cfg['mem_threshold'])))
                    text_internal = "process killed: {2}\nlogin node: {0}, " \
                                  "loadaverage: {1}," \
                                  "process: {2}, pid: {3}, " \
                                  "user: {4}, rss:{5}".format(
                                      nodename, load1, ps_comm,
                                      ps_pid, ps_uid,
                                      byteshuman.bytes2human(int(ps_rss)*1024))


                # user notification
                utils.notification(text,
                                   To=[ps_uid+cfg['emailDomain']],
                                   From=cfg['msg_from'],
                                   Cc=[],
                                   subj=cfg['msg_subj'],
                                   smtpHost=cfg['smtpHost'])
                text_combined[0] += text_internal + "\n" 

        elif action['action'] == 'internal_notification' and args.no_noop:
            if not _notification_sent(cfg['logfile'], action['user'], action['pid'],
                                      action['comm'], action['reason'], now, 3600):
                if action['reason'] == 'threadcount exceeded':
                    text_internal = "High number of threads for user: {0} on login node: {1}, " \
                                "process count: {2}, " \
                                "thread count: {3} ".format(
                                      action['user'], nodename,
                                      action['procs'], action['threads'])
                else:
                    text_internal = "IO high on login node: {0}, " \
                                "dev: {1}, " \
                                "bw_dev: {2}, " \
                                "top process - user: {3}, command: {4}, pid: {5}, bw_ps: {6}".format(
                                      nodename, action['dev'], action['bw_dev'], action['user'],
                                      action['comm'], action['pid'], action['bw_ps'])
                text_combined[1] += text_internal + "\n" 
                
                _logger.warning("Internal Notification sent - User: %s, pid: %s, " \
                         "cmd: %s, reason: %s", action['user'], action['pid'], 
                         action['comm'], action['reason'])
    # send internal notifications
    for msg in text_combined:
        if msg and args.no_noop:
            utils.notification(msg,
                               To=cfg['msg_cc'],
                               From=cfg['msg_from'],
                               Cc=[],
                               subj=cfg['msg_subj'],
                               smtpHost=cfg['smtpHost'])


    _logger.info("Script ends here")

def _notification_sent(logfile, user, pid, cmd, reason, now, secs):

    prog_t = re.compile(r'^\[(.*),.*\] .*')
    line = "Internal Notification sent - User: {}, pid: {}, " \
                    "cmd: {}, reason: {}".format(user, pid, cmd, reason)
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


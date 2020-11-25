#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""psman is  process management on a shared host(e.g. cluster login nodes, 
worker nodes).

On login nodes, it identifies hogging process in terms of cpu, memory and 
IO consumptions with configurable thresholds and take actions againt them. 
Actions include terminating the process, sending notifications to the 
operations team, end user as well as dynamically adjusting cgroup settings 
to limit the impact of hogging processes.
on worker nodes, it checks if the user process are in line with the resource
management system(job scheduler). examples include: 1) request more than 
actual nead in which case it's a waste. 2) run jobs outside of resource 
management system.

Run as a daemon to periodically enforce the rules or run as a command

    #list procs that exceeds configured threshold on login node
    psman -m login
    # run as a daemon with 10s sleep in between iterations
    psman -d 10 -m login
    #take configured actions on the procs exceeding configured thresholds
    psman -m login -v --no-noop
"""

from __future__ import division, print_function, absolute_import

import argparse
import sys
import logging
import time
import signal
import daemon
import daemon.pidfile
import yaml


from psman import __version__

from psman import worker_node

from psman import ps



__author__ = "Fengping Hu"
__copyright__ = "Fengping Hu"
__license__ = "none"

_logger = logging.getLogger(__name__)


def get_parser():
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(usage=__doc__)
        #description=__doc__)
        #formatter_class=argparse.RawDescriptionHelpFormatter)
        #description=("check IO status. Network usage per interface is get "
        #      "from zabbix. Network usage per process based on libpcap and nethogs")
    parser.add_argument(
        '-m',
        dest="mode",
        help="login node or worker node",
        choices=["login", "worker"],
        default='login')
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-d',
        dest="daemon",
        #action="store_true",
        default=0,
        help="run as daemon and sleep DAEMON seconds between iterations",
        type=int)
    group.add_argument(
        '-l', "--log",
        action="store_true",
        help="log to file(only for cmd mode, always log to file in daemon mode)",
        default=False)
    parser.add_argument(
        '-c',
        dest="configfile",
        help="configfile path(defult /usr/local/etc/psmancfg.yaml)",
        default='/usr/local/etc/psmancfg.yaml')
    group1 = parser.add_argument_group('worker node', 'worker node arguments')
    group2 = parser.add_argument_group('login node', 'login node arguments')
    group1.add_argument(
        '--idle-thold',
        dest="n",
        help="idle threshold in seconds",
        default=100,
        type=int)
    group2.add_argument(
        '-z',
        dest="z",
        help="zabbix history of past x minutes(net bandwidth data)",
        default=2,
        type=int)
    group2.add_argument(
        '-n',
        dest="n",
        help="collect io data for x seconds",
        default=4,
        type=int)
    #group = parser.add_mutually_exclusive_group()
    group2.add_argument(
        "--net",
        action="store_true",
        help="include network bw comsuption check",
        default=False)
#    group2.add_argument(
#        "-i", "--include",
#        action="store_true",
#        help="include exempted processes when show tops",
#        default=False)
    parser.add_argument(
        "--no-noop",
        action="store_true",
        help="not in noop mode, proper actions including procs "
        "termination and user notifications will be taken as needed",
        default=False)

    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        default=logging.WARN,
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    parser.add_argument(
        '--version',
        action='version',
        version='psman {ver}'.format(ver=__version__))
    return parser


def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = get_parser()
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    #logformat = "[%(asctime)s] %(name)-12s: %(levelname)-8s %(message)s"
    logformat = "%(name)-12s: %(levelname)-8s %(message)s"
    logging.basicConfig(level=loglevel, stream=sys.stdout,
                        format=logformat, datefmt="%Y-%m-%d %H:%M:%S")

def shutdown(signum, frame):
    """
    shutdown daemon on signal
    """
    sys.exit(0)

def main(args):
    """Main entry point allowing external calls
    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)

    if args.mode == "login":
        from psman import netio
        from psman import login_node

    cfg = {"logfile": "/tmp/psman.log"
          }

    setup_logging(args.loglevel)

    #_logger.debug("arguments: %s", args)
    print("arguments: %s", args)
    cfg_file = {}
    try:
        with open(args.configfile, 'r') as ymlfile:
            if hasattr(yaml, 'FullLoader'):
                cfg_file = yaml.load(ymlfile, Loader=yaml.FullLoader)
            else:
                cfg_file = yaml.load(ymlfile)
    except EnvironmentError as e:
        _logger.debug("No config file is loaded, %s", e)
        #print ("No config file is loaded: ", e)
        #pass

    cfg.update(cfg_file)

    setup_logging(logging.WARN)
    _logger.setLevel(args.loglevel)
    ps._logger.setLevel(args.loglevel)
    if args.mode == "login":
        netio._logger.setLevel(args.loglevel)
        login_node._logger.setLevel(args.loglevel)
    worker_node._logger.setLevel(args.loglevel)

    if args.log or args.daemon:
        try:
            fh = logging.FileHandler(cfg['logfile'])
        except Exception as e:
            _logger.error("failed to setup logfile: %s", e)
            return 1

        formatter = logging.Formatter(
            '[%(asctime)s] %(name)-12s: %(levelname)-8s %(message)s')
        fh.setFormatter(formatter)
        _logger.addHandler(fh)
        ps._logger.addHandler(fh)
        if args.mode == "login":
            netio._logger.addHandler(fh)
            login_node._logger.addHandler(fh)
        elif args.mode == "worker":
            worker_node._logger.addHandler(fh)


    if not args.daemon:
        if args.mode == "login":
            login_node.psman_run(args, cfg)
        elif args.mode == "worker":
            worker_node.psman_run(args, cfg)
    else:
        context = daemon.DaemonContext(
            #working_directory='/var/lib/psman',
            #umask=0o002,
            #pidfile=lockfile.FileLock('/var/run/psman.pid'),
            signal_map={
                signal.SIGTERM: shutdown,
                signal.SIGTSTP: shutdown
                },
            pidfile=daemon.pidfile.PIDLockFile('/var/run/psman.pid'),
            )

        #mail_gid = grp.getgrnam('mail').gr_gid
        #context.gid = mail_gid
        #important_file = open('spam.data', 'w')
        #interesting_file = open('eggs.data', 'w')
        context.files_preserve = [fh.stream, sys.stdout]

        with context:
            while True:
                try:
                    if args.mode == "login":
                        login_node.psman_run(args, cfg)
                    elif args.mode == "worker":
                        worker_node.psman_run(args, cfg)
                    time.sleep(args.daemon)
                except Exception as e:
                    _logger.error("psman iteration failed: %s", e)
                    sys.exit(1)

def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()

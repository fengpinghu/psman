=====
psman
=====

psman is process management on a shared host(e.g. cluster login nodes). 


Description
===========

psman is  process management on a shared host(e.g. cluster login nodes).

It identifies hogging process in terms of cpu, memory and IO consumptions
with configurable thresholds and take actions againt them. Actions include
terminating the process, sending notifications to the operations team, end
user as well as dynamically adjusting cgroup settings to limit the
impact of hogging processes.

It can run as a cron to periodically enforcing the rules or run as an command
to inspect the top resource consuming processes and users.

    Typical usage example:
    #list procs that exceeds configured threshold
    psman
    # list top resource cosuming procs excludeing the exempted ones
    psman -t
    #list top resource consuming procs including the exempted ones
    psman -t -i
    #take configured actions on the procs that exceeds configured thresholds
    psman -v --no-noop


Note
====

This project has been set up using PyScaffold 2.5.10. For details and usage
information on PyScaffold see http://pyscaffold.readthedocs.org/.

=====
psman
=====

psman is process management tool for use on a shared host (e.g. cluster login nodes). 


Description
===========

psman is  process management tool for use on a shared host (e.g. cluster login nodes).

It identifies hogging processes in terms of cpu, memory and IO consumption
with configurable thresholds and takes actions againt them. Actions include
terminating the process, sending notifications to the operations team, notifying the end
user, as well as dynamically adjusting cgroup settings to limit the
impact of the hogging processes.

It can run as a cron job to periodically enforce the rules or be run as an command
to inspect the top resource-consuming processes and users.

.. code-block:: shell-session

    # 1) list procs that exceeds configured threshold
    psman
    # 2) list top resource cosuming procs excludeing the exempted ones
    psman -t
    # 3) list top resource consuming procs including the exempted ones
    psman -t -i
    # 4) take configured actions on the procs that exceeds configured thresholds
    psman -v --no-noop


Note
====

This project has been set up using PyScaffold 2.5.10. For details and usage
information on PyScaffold see http://pyscaffold.readthedocs.org/.

# -*- coding: utf-8 -*-
""" netio Collects network io data per process.

It uses the Nethogs library. The Nethogs library operates via a callback.
The callback here stores the data in a list. The start function will start
the data collection thread so it doesn't block the main thread. Call wait
before processing the data to make sure the data collection is finished.

    Typical usage example:
    start()
    wait()
    access the data in the list procs

"""

# This code is adapted from the python-wrapper.py module that can be found at
# https://github.com/raboof/nethogs/blob/master/contrib/python-wrapper.py

import ctypes
import threading
import logging


_logger = logging.getLogger(__name__)


# You can use this to monitor only certain devices, like:
# device_names = ['enp4s0', 'docker0']
device_names = []

# LIBRARY_NAME has to be exact, although it doesn't need to include the full path.
# The version tagged as 0.8.5 (download link below) builds a library with this name.
# https://github.com/raboof/nethogs/archive/v0.8.5.tar.gz
LIBRARY_NAME = '/usr/lib/libnethogs.so.0.8.5'

# EXPERIMENTAL: Optionally, specify a capture filter in pcap format (same as
# used by tcpdump(1)) or None. See `man pcap-filter` for full information.
# Note that this feature is EXPERIMENTAL (in libnethogs) and may be removed or
# changed in an incompatible way in a future release.
# example:
# FILTER = 'port 80 or port 8080 or port 443'
FILTER = None



# Here are some definitions from libnethogs.h
# https://github.com/raboof/nethogs/blob/master/src/libnethogs.h
# Possible actions are NETHOGS_APP_ACTION_SET & NETHOGS_APP_ACTION_REMOVE
# Action REMOVE is sent when nethogs decides a connection or a process has died. There are two
# timeouts defined, PROCESSTIMEOUT (150 seconds) and CONNTIMEOUT (50 seconds). AFAICT, the latter
# trumps the former so we see a REMOVE action after ~45-50 seconds of inactivity.
class Action():
    SET = 1
    REMOVE = 2

    MAP = {SET: 'SET', REMOVE: 'REMOVE'}

class LoopStatus():
    """Return codes from nethogsmonitor_loop()"""
    OK = 0
    FAILURE = 1
    NO_DEVICE = 2

    MAP = {OK: 'OK', FAILURE: 'FAILURE', NO_DEVICE: 'NO_DEVICE'}

# The sent/received KB/sec values are averaged over 5 seconds; see PERIOD in nethogs.h.
# https://github.com/raboof/nethogs/blob/master/src/nethogs.h#L43
# sent_bytes and recv_bytes are a running total
class NethogsMonitorRecord(ctypes.Structure):
    """ctypes version of the struct of the same name from libnethogs.h"""
    _fields_ = (('record_id', ctypes.c_int),
                ('name', ctypes.c_char_p),
                ('pid', ctypes.c_int),
                ('uid', ctypes.c_uint32),
                ('device_name', ctypes.c_char_p),
                ('sent_bytes', ctypes.c_uint32),
                ('recv_bytes', ctypes.c_uint32),
                ('sent_kbs', ctypes.c_float),
                ('recv_kbs', ctypes.c_float),
               )


def dev_args(devnames):
    """
    Return the appropriate ctypes arguments for a device name list, to pass
    to libnethogs ``nethogsmonitor_loop_devices``. The return value is a
    2-tuple of devc (``ctypes.c_int``) and devicenames (``ctypes.POINTER``)
    to an array of ``ctypes.c_char``).

    :param devnames: list of device names to monitor
    :type devnames: list
    :return: 2-tuple of devc, devicenames ctypes arguments
    :rtype: tuple
    """
    devc = len(devnames)
    devnames_type = ctypes.c_char_p * devc
    devnames_arg = devnames_type()
    for idx, val in enumerate(devnames):
        devnames_arg[idx] = (val + chr(0)).encode('ascii')
    return ctypes.c_int(devc), ctypes.cast(
        devnames_arg, ctypes.POINTER(ctypes.c_char_p)
    )


def run_monitor_loop(lib, devnames):
    # Create a type for my callback func. The callback func returns void (None), and accepts as
    # params an int and a pointer to a NethogsMonitorRecord instance.
    # The params and return type of the callback function are mandated by nethogsmonitor_loop().
    # See libnethogs.h.
    CALLBACK_FUNC_TYPE = ctypes.CFUNCTYPE(
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(NethogsMonitorRecord)
    )

    filter_arg = FILTER
    if filter_arg is not None:
        filter_arg = ctypes.c_char_p(filter_arg.encode('ascii'))

    if len(devnames) < 1:
        # monitor all devices
        rc = lib.nethogsmonitor_loop(
            CALLBACK_FUNC_TYPE(network_activity_callback),
            filter_arg
        )
    else:
        devc, devicenames = dev_args(devnames)
        rc = lib.nethogsmonitor_loop_devices(
            CALLBACK_FUNC_TYPE(network_activity_callback),
            filter_arg,
            devc,
            devicenames,
            ctypes.c_bool(False)
        )

    if rc != LoopStatus.OK:
        #print('nethogsmonitor_loop returned {}'.format(LoopStatus.MAP[rc]))
        _logger.info('nethogsmonitor_loop returned %s', LoopStatus.MAP[rc])
    else:
        #print('exiting monitor loop')
        _logger.debug('exiting monitor loop')


def network_activity_callback(action, data):
    global procs
    #print(datetime.datetime.now().strftime('@%H:%M:%S.%f'))

    # Action type is either SET or REMOVE. I have never seen nethogs send an unknown action
    # type, and I don't expect it to do so.
    action_type = Action.MAP.get(action, 'Unknown')
    if action_type == 'SET':
        procs.append(data)
#    print('Action: {}'.format(action_type))
#    print('Record id: {}'.format(data.contents.record_id))
#    print('Name: {}'.format(data.contents.name))
#    print('PID: {}'.format(data.contents.pid))
#    print('UID: {}'.format(data.contents.uid))
#    print('Device name: {}'.format(data.contents.device_name.decode('ascii')))
#    print('Sent/Recv bytes: {} / {}'.format(data.contents.sent_bytes, data.contents.recv_bytes))
#    print('Sent/Recv kbs: {} / {}'.format(data.contents.sent_kbs, data.contents.recv_kbs))
#    print('-' * 30)

#############       Main begins here      ##############


_lib = ctypes.CDLL(LIBRARY_NAME)

_monitor_thread = threading.Thread(
    target=run_monitor_loop, args=(_lib, device_names,)
)

procs = []

def start(t=2):
    """ start the data collection thread
    """
    _monitor_thread.start()
    threading.Timer(t, _lib.nethogsmonitor_breakloop).start()


def wait(t=2):
    """ wait for the data collection thread to finish
    """
    done = False
    w = 0
    while not done:
        _monitor_thread.join(0.3)
        w += 0.3
        done = not _monitor_thread.is_alive()
        if w > t + 0.3:
            _logger.warning("netio thread waited longer than should %d", w)

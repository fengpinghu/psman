# -*- coding: utf-8 -*-
"""utils provides misc utils to be used by the psman program


"""

import subprocess

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def notification(text,
                 From='',
                 To=[],
                 Cc=[],
                 subj='',
                 smtpHost=''
                ):
    """Send out Notifications"""

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subj
    msg["From"] = From
    msg["To"] = ", ".join(To)
    msg["Cc"] = ", ".join(Cc)
    part1 = MIMEText(text, 'plain')
    msg.attach(part1)
    # send the email
    rcpt = To + Cc
    s = smtplib.SMTP(smtpHost)
    s.sendmail(From, rcpt, msg.as_string())
    s.quit()


def get_group_members(grp):
    """ get members of a group """
    members = []
    cmd = "getent group "+grp
    res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, \
                    stderr=subprocess.PIPE)
    out, error = res.communicate()
    if out:
        members = out.split(":")[3].strip().split(',')
    return members

def get_user_name(uid):
    """ get name from uid """
    name = ""
    cmd = "getent passwd {0} | cut -d: -f1".format(uid)
    res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, \
                   stderr=subprocess.PIPE)
    out, error = res.communicate()
    if out:
        #name=out.split(' ')[0]
        name = out.rstrip()
    return name

def get_user_firstname(uid):
    """ get name from uid """
    name = ""
    cmd = "getent passwd {0} | cut -d: -f5".format(uid)
    res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, \
                   stderr=subprocess.PIPE)
    out, error = res.communicate()
    if out:
        name = out.split(' ')[0]
    return name

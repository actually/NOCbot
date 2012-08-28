#!/usr/bin/env python
"""
adminchannel.py - Based on the Jenni Admin Channel Module
Copyright 2010-2011, Michael Yanovich (yanovich.net) and Alek Rollyson.
Licensed under the Eiffel Forum License 2.

More info:
 * Jenni: https://github.com/myano/jenni/
 * Phenny: http://inamidst.com/jenni/

Beefed up by Alek Rollyson. added functions for op, deop, voice, devoice.

Uses kerberos SSO Realms to verify that a nick is authenticated with, as well
as m5's admin list as a double verification system. Should eliminate the possibility
of nick spoofing. May only work with freenode, hasn't been tested on other networks.
"""

import re

auth_list = []
admins = []

def op(jenni, input):
    """
    Command to op users in a room. If no nick is given,
    jenni will op the nick who sent the command
    """
    if not input.admin or not input.sender.startswith('#'):
        return
    nick = input.group(2)
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        channel = input.sender
        if not nick:
            nick = input.nick
        jenni.write(['MODE', channel, "+o", nick])
op.rule = (['op'], r'(\S+)?')
op.priority = 'low'

def deop(jenni, input):
    """
    Command to deop users in a room. If no nick is given,
    jenni will deop the nick who sent the command
    """
    if not input.admin or not input.sender.startswith('#'):
        return
    nick = input.group(2)
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        channel = input.sender
        if not nick:
            nick = input.nick
        jenni.write(['MODE', channel, "-o", nick])
deop.rule = (['deop'], r'(\S+)?')
deop.priority = 'low'

def invite(jenni, input):
    """
    Command to invite users in a room. If no nick is given,
    jenni will invite the nick who sent the command
    """
    if not input.admin or not input.sender.startswith('#'):
        return
    nick = input.group(2)
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        channel = input.sender
        if not nick:
            nick = input.nick
        jenni.write(['INVITE', nick, channel])
        jenni.say("Inviting " + nick + " to " + channel)
invite.rule = (['invite'], r'(\S+)?')
invite.priority = 'low'

def voice(jenni, input):
    """
    Command to voice users in a room. If no nick is given,
    jenni will voice the nick who sent the command
    """
    if not input.admin or not input.sender.startswith('#'):
        return
    nick = input.group(2)
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        channel = input.sender
        if not nick:
            nick = input.nick
        jenni.write(['MODE', channel, "+v", nick])
voice.rule = (['voice'], r'(\S+)?')
voice.priority = 'low'

def devoice(jenni, input):
    """
    Command to devoice users in a room. If no nick is given,
    jenni will devoice the nick who sent the command
    """
    if not input.admin or not input.sender.startswith('#'):
        return
    nick = input.group(2)
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        channel = input.sender
        if not nick:
            nick = input.nick
        jenni.write(['MODE', channel, "-v", nick])
devoice.rule = (['devoice'], r'(\S+)?')
devoice.priority = 'low'

def auth_krb(jenni, input):
    """
    This will authenticate a user off of AD Credentials
    If checkPassword returns True, add user to auth_list
   
    You must have sso_service and sso_realm in ~/.phenny/default.py
    """
    global auth_list
    import kerberos
    split_it = []
    nick = input.nick
    line = input.group(0)
    string_line = str(line)
    for item in string_line.split():
        split_it.append(item)
    username = split_it[2]
    password = split_it[3]
    # Can only be done in prvmsg by an admin
    if input.sender.startswith('#'):
	return
    if input.admin:
	if nick in auth_list:
	    return
	else:
            jenni.say(nick + " is being authenticated.")
	    if kerberos.checkPassword(username,password,input.sso_service,input.sso_realm):
                jenni.say(nick + " authenticated.")
   	        auth_list.append(nick)
    else:
	jenni.say(nick + " NOT authorized!")
	auth_list.remove(nick)
auth_krb.rule = (['auth'], r'(\S+) (.+)')
auth_krb.commands = ['auth']
auth_krb.priority = 'low'

def auth_check(jenni, nick, target=None):
    """
    Checks if nick is on the auth list and returns true if so
    """
    global auth_list
    if target == jenni.config.nick:
        return 0 
    elif nick in auth_list:
        return 1

def deauth(nick):
    """
    Remove pepole from the deauth list.
    """
    global auth_list
    if nick in auth_list:
        a = auth_list.index(nick)
        del(auth_list[a])

def deauth_quit(jenni, input):
    deauth(input.nick)
deauth_quit.event = 'QUIT'
deauth_quit.rule = '.*'

def deauth_part(jenni, input):
    deauth(input.nick)
deauth_part.event = 'PART'
deauth_part.rule = '.*'

def deauth_nick(jenni, input):
    deauth(input.nick)
deauth_nick.event = 'NICK'
deauth_nick.rule = '.*'

def kick(jenni, input):
    if not input.admin: return
    nick = input.nick
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        text = input.group().split()
        argc = len(text)
        if argc < 2: return
        opt = text[1]
        nick = opt
        channel = input.sender
        reasonidx = 2
        if opt.startswith('#'):
            if argc < 3: return
            nick = text[2]
            channel = opt
            reasonidx = 3
        reason = ' '.join(text[reasonidx:])
        if nick != jenni.config.nick:
            jenni.write(['KICK', channel, nick, reason])
kick.commands = ['kick']
kick.priority = 'high'

def configureHostMask (mask):
    if mask == '*!*@*': return mask
    if re.match('^[^.@!/]+$', mask) is not None: return '%s!*@*' % mask
    if re.match('^[^@!]+$', mask) is not None: return '*!*@%s' % mask

    m = re.match('^([^!@]+)@$', mask)
    if m is not None: return '*!%s@*' % m.group(1)

    m = re.match('^([^!@]+)@([^@!]+)$', mask)
    if m is not None: return '*!%s@%s' % (m.group(1), m.group(2))

    m = re.match('^([^!@]+)!(^[!@]+)@?$', mask)
    if m is not None: return '%s!%s@*' % (m.group(1), m.group(2))
    return ''

def ban (jenni, input):
    """
    This give admins the ability to ban a user.
    The bot must be a Channel Operator for this command to work.
    """
    if not input.admin: return
    nick = input.nick
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        text = input.group().split()
        argc = len(text)
        if argc < 2: return
        opt = text[1]
        banmask = opt
        channel = input.sender
        if opt.startswith('#'):
            if argc < 3: return
            channel = opt
            banmask = text[2]
        banmask = configureHostMask(banmask)
        if banmask == '': return
        jenni.write(['MODE', channel, '+b', banmask])
ban.commands = ['ban']
ban.priority = 'high'

def unban (jenni, input):
    """
    This give admins the ability to unban a user.
    The bot must be a Channel Operator for this command to work.
    """
    if not input.admin: return
    nick = input.nick
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        text = input.group().split()
        argc = len(text)
        if argc < 2: return
        opt = text[1]
        banmask = opt
        channel = input.sender
        if opt.startswith('#'):
            if argc < 3: return
            channel = opt
            banmask = text[2]
        banmask = configureHostMask(banmask)
        if banmask == '': return
        jenni.write(['MODE', channel, '-b', banmask])
unban.commands = ['unban']
unban.priority = 'high'

def quiet (jenni, input):
    """
    This gives admins the ability to quiet a user.
    The bot must be a Channel Operator for this command to work
    """
    if not input.admin: return
    text = input.group().split()
    argc = len(text)
    if argc < 2: return
    opt = text[1]
    quietmask = opt
    channel = input.sender
    if opt.startswith('#'):
       if argc < 3: return
       quietmask = text[2]
       channel = opt
    quietmask = configureHostMask(quietmask)
    if quietmask == '': return
    jenni.write(['MODE', channel, '+q', quietmask])
quiet.commands = ['quiet']
quiet.priority = 'high'

def unquiet (jenni, input):
    """
    This gives admins the ability to unquiet a user.
    The bot must be a Channel Operator for this command to work
    """
    if not input.admin: return
    text = input.group().split()
    argc = len(text)
    if argc < 2: return
    opt = text[1]
    quietmask = opt
    channel = input.sender
    if opt.startswith('#'):
        if argc < 3: return
        quietmask = text[2]
        channel = opt
    quietmask = configureHostMask(quietmask)
    if quietmask == '': return
    jenni.write(['MODE', opt, '-q', quietmask])
unquiet.commands = ['unquiet']
unquiet.priority = 'high'

def kickban (jenni, input):
    """
    This gives admins the ability to kickban a user.
    The bot must be a Channel Operator for this command to work
    .kickban [#chan] user1 user!*@* get out of here
    """
    if not input.admin: return
    mynick = input.nick     
    verify = auth_check(jenni, input.nick, mynick)
    if verify:
        text = input.group().split()
        argc = len(text)
        if argc < 4: return
        opt = text[1]
        nick = opt
        mask = text[2]
        reasonidx = 3
        if opt.startswith('#'):
            if argc < 5: return
            channel = opt
            nick = text[2]
            mask = text[3]
            reasonidx = 4
        reason = ' '.join(text[reasonidx:])
        mask = configureHostMask(mask)
        if mask == '': return
        jenni.write(['MODE', channel, '+b', mask])
        jenni.write(['KICK', channel, nick, ' :', reason])
kickban.commands = ['kickban', 'kb']
kickban.priority = 'high'

def topic(jenni, input):
    """
    This gives admins the ability to change the topic.
    Note: One does *NOT* have to be an OP, one just has to be on the list of
    admins.
    """
    nick = input.nick
    if not input.admin:
        return
    verify = auth_check(jenni, input.nick, nick)
    if verify:
        text = input.group().split()
        topic = ' '.join(text[1:])
        if topic == '':
            return
        channel = input.sender
        jenni.write(['TOPIC', channel], '%s' % (topic))
        return
topic.commands = ['topic']
topic.priority = 'low'

if __name__ == '__main__':
    print __doc__.strip()


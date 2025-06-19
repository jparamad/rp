#!/usr/bin/python
# RP - by John Paramadilok (2025.06)
# This script securely stores recovery phrases and codes.
# Backup files require manual encryption for protection.
#
# Dependencies:
#   -
#   - os.system and subprocess uses shasum, shred, tar
#   - requests, pyperclip package (pip)
#
# Notes:
#   v.0.1 - Initial code development
#
# Menu Options:
#    add      Adds passwd to list
#    del      Deletes entry from list
#    find     Searches for key value
#    h        Displays help menu
#    q        Quit program
#    num      Displays number of entries in list
#    run      Runs program
#    usr      Generates unique usernames for key value
#
# Output:
#   run - processes recovery phrase/code for use and ouputs values
#         to term and clipboard one at a time.
#   num - provides number of entries within the file list
#            << Returned (1) entries.
#   usr - generates a unique username to be stored as key instead of
#         one that may be attributable to specific accounts in the
#         event of loss or compromise.
#            > mode 0 uses the first eight char of sha1 (default)
#            > mode 1 uses the first eight char of sha256
#            > mode 2 uses the first ten char of sha512
#####################################################################

import hashlib
import os
import requests
import base64
import datetime
import subprocess
import pyperclip

# Global Vars
v = 'v.0.1'
log_file = './rp.log'       # Log file
gpg_file = './rp.gpg'       # GPG file
hash_file = './rp.sha512'   # Hash file
fval = 0

def fdecode_func():
    """Process Base Decoding of Log File Content"""
    with open(log_file, 'r') as f:
        fcontent = f.read()
    fcontent_str = fcontent.encode('ascii')
    fd = base64.b64decode(fcontent_str)
    fdd = fd.decode('ascii')
    return fdd


def fencode_func(log_data, fnew):
    """Process Base Encoding of File Content"""
    if (str(os.path.exists(log_file)) == 'True') and (fnew == 0):
        fdd = fdecode_func()
        fd = fdd + log_data
    else:
        fd = log_data
    fde = fd.encode('ascii')
    fe = base64.b64encode(fde)
    fed = fe.decode('ascii')
    f = open(log_file, 'w')
    f.write(fed)
    f.close()
    print('<< Log file successfully updated.')


def fenc_func(log_file, gpg_file):
    os.system('gpg -o ' + gpg_file + ' --cipher-algo aes256 -c ' + log_file)
    if str(os.path.isfile(gpg_file)) == 'True':
        print('<< ' + gpg_file + ' created')
    else:
        print('[ERROR: Unable to locate encrypted file]')


def search_func(sval, fval):
    """Search for Values in Log File"""
    fdd = fdecode_func()
    search_arr = []
    for i in fdd.split('\n'):
        search_arr.append(i)
    res = [i for i in search_arr if sval in i]

    if not len(sval):
        res_len = len(res) - 1
    else:
        res_len = len(res)

    print('Search results ' + '(' + str(res_len) + ')')

    if len(res):
        if fval == 0:
            return(res_len)
        elif fval == 1:
            for i in search_arr:
                if sval in i:
                    print(i)
                    j = search_arr.index(i)
                    rin = input('Delete? ')
                    if rin == 'y' or rin == 'Y':
                        search_arr.pop(j)
                        log_data = '\n'.join([str(i) for i in search_arr])
                        fnew = 1
                        fencode_func(log_data, fnew)
                        print('Successfully removed element [' + str(j) + '].')
                        fval = 0
                        break
                    else:
                        print('<< Removal aborted.')
        elif fval == 2:
            fval = 0
            for i in res:
                return(i)
    else:
        print('<< No matching keys found.')


def hlist_func():
    """Process Base Decoding of Log File Content"""
    # with open(flist, 'r') as f:
    #     fcontent = f.read()
    hlist = fdecode_func()
    hlist = hlist.encode('ascii')
    return hlist


def log_func(rp):
    """Log File Manipulation"""
    d = datetime.datetime.now()

    log_list = '-'.join(rp)
    log_str = '{' + log_list + '}'

    w = input('Write to log file (y/n)? ')
    if (w == 'y') or (w == 'Y'):
        log_data = ('[' + v + '] ' + d.strftime('%y%m%d') + ': ' + log_str + '\n')
        fnew = 0
        fencode_func(log_data, fnew)

    return log_str


def add_func():
    fval = 0
    k = input('Key=> ')
    if str(os.path.exists(log_file)) == 'True':
        log_data = search_func(k, fval)
        if str(log_data) != 'None':
            print('<< Matching key exists. Unique keys are required.')
            return
    else:
        print('[WARNING: No log file detected]')
        log_data = 'None'
        rin = input('Create log file? ')
        if rin == 'y' or rin == 'Y':
            f = open(log_file, "x")
            if str(os.path.exists(log_file)) == 'True':
                print('<< ' + log_file + ' created.')
            else:
                print('[ERROR: Issues creating log file]')

    rp = []
    print('')

    c = input('Count=> ')
    if not len(c):
        p = k
        c = 0
        rp.insert(c, p)
        while p != '':
            c += 1
            p = input(str(c) + '. ')
            rp.insert(c, p)
        rp = rp[:-1]
    else:
        c = int(c)
        c += 1

        for i in range(c):
            if i != 0:
                rp_add = input(str(i) + '. ')
                rp.insert(i, rp_add)
            else:
                rp.insert(i, k)

    rp_len = len(rp)
    os.system('clear')
    print('Verify code phrases. ====================')
    for i in range(rp_len):
        if i != 0:
            print(str(i) + '. ' + rp[i])
    print('=========================================')
    print('Key= ' + rp[0])

    fnew = 0
    log_func(rp)


def del_func():
    """Removes Values in Log File"""
    sval = input('rp-delete>> ')
    fval = 1
    search_func(sval, fval)


def num_func(num):
    """Displays list count"""
    if str(os.path.exists(log_file)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        hlist = hlist_func()
        hlist = hlist.upper()
        list = hlist.decode('utf8').strip()
        pass_list = []

        # Converts entries in list variable to list
        for i in list.split('\n'):
            pass_list.append(i)

        list_len = len(pass_list)

        if num == 0:
            print('>> Searching db for (' + str(list_len) + ') entries.')
            return pass_list
        else:
            print('<< Returned (' + str(list_len) + ') entries.')


def run_func():
    fval = 2

    """Processes RP for Display"""
    if str(os.path.exists(log_file)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        k = input('Key>> ')

        log_data = search_func(k, fval)

        if str(log_data) == 'None':
            return

        log_data = log_data[16:]
        log_data = log_data.replace('{', '')
        log_data = log_data.replace('}', '')
        x = log_data.count('-')

        log_data = log_data.split('-', int(x))
        log_data.pop(0)

        j = 1
        for i in log_data:
            print(str(j) + '. ' + i)
            j += 1
            if ostype == 'Cygwin':
                pyperclip.copy(i)
            elif ostype == 'Android':
                os.system('termux-clipboard-set "' + i + '"')
            input()



def find_func():
    fval = 0

    """Determines if RP Exists for a given Key"""
    if str(os.path.exists(log_file)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        k = input('Key>> ')

        count = search_func(k, fval)
        if str(count) == 'None': count = 0
        count = int(count)
        if count == 1:
            print('<< ' + str(count) + ' match found!')
        elif count > 1:
            print('<< ' + str(count) + ' matches found!')
        else:
            print('<< Nothing found.')


def usr_func():
    """Generates Uname Value"""
    uname = input('uname=> ')
    mode = input('mode=> ')
    if mode == '': mode = 0
    mode = int(mode)
    u_str = uname.encode('ascii')

    if mode == 2:
        md = hashlib.sha512()
    elif mode == 1:
        md = hashlib.sha256()
    else:
        md = hashlib.sha1()

    md.update(u_str)
    u = md.hexdigest()

    if mode == 2:
        uname = u[:10]
    else:
        uname = u[:8]

    if ostype == 'Cygwin':
        pyperclip.copy(uname)
    elif ostype == 'Android':
        os.system('termux-clipboard-set "' + uname + '"')
    print('<< ' + uname)


def bak_func():
    """Backup Log File to tarball"""
    bak_path = './bak/'
    hash_path = bak_path + 'rp.sha256'
    d = datetime.datetime.now()
    tar_path = (bak_path + 'rp_' + d.strftime('%y%m%d%H%M') + '.tar.bz2')

    if str(os.path.isdir(bak_path)) != 'True':
        print('[WARNING: Backup dir does not exist]')
        os.system('mkdir ' + bak_path)
        if str(os.path.isdir(bak_path)) == 'True':
            print('<< Backup directory created.')
        else:
            print('[ERROR: Unable to locate directory]')

    if str(os.path.exists(log_file)) != 'True':
        print('Log file not found. Nothing to backup.')
        return

    if str(os.path.exists(tar_path)) == 'True':
        print(tar_path + ' exists. Wait a minute and run again.')
    else:
        status = subprocess.run(['sha256sum', log_file], stdout=subprocess.PIPE)
        hash_val = status.stdout.decode('utf-8')

        f = open(hash_path, 'w')
        f.write(hash_val)
        f.close()

        subprocess.run(['sha256sum', '-c', hash_path])
        subprocess.run(['tar', '-cjf', tar_path, log_file, hash_path], stdout=subprocess.PIPE)
        print('<< ' + log_file + ' backed up to ' + tar_path)
        os.remove(hash_path)
        print('[WARNING: Backed up file was not encrypted. Select \'enc\' to encrypt.]')


def help_func():
    """Displays Main Help Menu"""
    print(' ')
    print('Menu Options:')
    print('  add      Adds passwd to list')
    print('  bak      Backup list')
    print('  del      Deletes list')
    print('  h        Displays help menu')
    print('  q        Quit program')
    print('  num      Displays number of entries in list')
    print('  run      Recovers Phrases and Codes')
    print('  usr      Generates uniqie username from input')
    print(' ')


def menu_func():
    """Runs Menu-based Interface"""
    cin = input('rp>> ')
    while cin != 'q':
        match cin:
            case 'add':
                add_func()
            case 'del':
                del_func()
            case 'enc':
                enc_func()
            case 'num':
                num = 1
                num_func(num)
            case 'usr':
                usr_func()
            case 'find':
                find_func()
            case 'run':
                run_func()
            case 'bak':
                bak_func()
            case 'h':
                help_func()
            case _:
                print('Invalid command. Enter \'h\' to display help menu.')
        cin = input('rp>> ')


def ver_func ():
    """Displays Code Version"""
    global ostype
    ostype = os.popen('uname -o').read()
    ostype = ostype.rstrip()

    print('[rp-' + v + ']' + ostype)


def main():
    """Main Function"""
    ver_func()

    if str(os.path.isfile(gpg_file)) == 'True':
        if str(os.path.isfile(log_file)) == 'True':
            print('[WARNING: Existing log file present]')
        else:
            f = (log_file)
            g = (gpg_file)
            os.system('gpg -o ' + f + ' -d ' + g)
            if str(os.path.isfile(log_file)) == 'True':
                print('<< ' + f + ' decrypted from ' + g)
                os.system('sha512sum ' + log_file + ' > ' + hash_file)
                if os.stat(hash_file).st_size != 0:
                    print('<< Log hash created.')
                else:
                    print('[ERROR: Log hash issue.]')
            else:
                # print('[WARNING: Skipping hash file creation.]')
                os.system('sha512sum ' + log_file + ' > ' + hash_file)
                if os.stat(hash_file).st_size != 0:
                    print('<< Log hash created.')
    else:
        print('[WARNING: Protected file not present]')
        rin = input('Create encrypted file? ')
        if rin == 'y' or rin == 'Y':
            if str(os.path.isfile(log_file)) == 'True':
                fenc_func(log_file, gpg_file)
            else:
                subprocess.run(['touch', log_file])
                fenc_func(log_file, gpg_file)

    menu_func()

    # Check log file integrity
    if str(os.path.isfile(gpg_file)) == 'True':
        hashcheck = os.popen('sha512sum -c ' + hash_file).read()
        hashcheck = hashcheck.rstrip()

        if str(hashcheck[-2:]) != 'OK':
            cin = input('Update log file? ')

            if cin == 'y' or cin == 'Y':
                if str(os.path.isfile(log_file)) == 'True':
                    orig_path = log_file
                    fenc_func(log_file, gpg_file)
                else:
                    print('[ERROR: Log file does not exist]')
    else:
        print('[WARNING: Skipping hash file check.]')

    # Clean log files
    if str(os.path.isfile(log_file)) == 'True':
        subprocess.run(['shred', '-fuz', log_file])
        print('<< Cleaning files.')
        if str(os.path.isfile(hash_file)) == 'True':
            subprocess.run(['shred', '-fuz', hash_file])

    if str(os.path.isfile(log_file)) != 'True':
        if str(os.path.isfile(hash_file)) != 'True':
            print('<< Log files not present.')
        else:
            print('[WARNING: Log hash may still be present]')
    else:
        print('[WARNING: Log file may still be present]')

    exit(0)



if __name__ == '__main__':
    main()
```text
# !/usr/bin/python
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
#####################################################################```

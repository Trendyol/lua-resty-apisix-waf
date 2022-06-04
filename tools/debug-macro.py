#!/usr/bin/env python3

import os
import sys
import re


def replace(oldstr, newstr, infile, dryrun=False):
    """
    Sed-like Replace function..
    Usage: pysed.replace(<Old string>, <Replacement String>, <Text File>)
    Example: pysed.replace('xyz', 'XYZ', '/path/to/file.txt')
    Example 'DRYRUN': pysed.replace('xyz', 'XYZ', '/path/to/file.txt', dryrun=True) #This will dump the output to STDOUT instead of changing the input file.
    """
    linelist = []
    with open(infile) as f:
        for item in f:
            newitem = re.sub(oldstr, newstr, item)
            linelist.append(newitem)
    if not dryrun:
        with open(infile, "w") as f:
            f.truncate()
            for line in linelist: f.writelines(line)
    elif dryrun:
        # for line in linelist: print(line, end='')
        pass
    else:
        exit("Unknown option specified to 'dryrun' argument, Usage: dryrun=<True|False>.")


def replace_file(oldstr, newstr, infile):
    items = None
    with open(infile) as f:
        items = f.read()
        items = re.sub(oldstr, newstr, items)
    with open(infile, "w") as f:
        f.write(items)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'clean':
        replace_file(infile="./lib/resty/waf.lua",
                     oldstr=r"if self\._debug == true then[\s\r\n]*ngx\.log\(.*?'] ', (.*)\)[\s\r\n]*end",
                     newstr=r'''--_LOG_\1''')
        for root, dirs, files in os.walk("./lib/resty/waf/"):
            for name in files:
                replace_file(infile=os.path.join(root, name),
                             oldstr=r"if waf\._debug == true then[\s\r\n]*ngx\.log\(.*?'\] ', (.*)\)[\s\r\n]*end",
                             newstr=r'''--_LOG_\1''')
    else:
        replace(infile="./lib/resty/waf.lua", oldstr='--_LOG_(.*)',
                newstr=r"if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "
                       r"\1) end")
        for root, dirs, files in os.walk("./lib/resty/waf/"):
            for name in files:
                replace(infile=os.path.join(root, name), oldstr='--_LOG_(.*)',
                        newstr=r"if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, "
                               r"'] ', \1) end")

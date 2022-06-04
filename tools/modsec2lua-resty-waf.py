#!/usr/bin/env python3

import json
import os.path
import sys
import re

import msc_pyparser
from msc_pyparser import MSCUtils as u


def empty():
    pass


expand_operators = {'@beginsWith': True,
                    '@contains': True,
                    '@containsWord': True,
                    '@endsWith': True,
                    '@eq': True,
                    '@ge': True,
                    '@gt': True,
                    '@le': True,
                    '@lt': True,
                    '@streq': True,
                    '@within': True,
                    }

if __name__ == '__main__':

    srcobj = "../../coreruleset/rules"
    dstobj = "."

    dt = u.getpathtype(dstobj)
    if dt == u.UNKNOWN:
        print("Unknown dest path!")
        sys.exit(-1)
    if dt == u.IS_FILE:
        print("Dest path is file!")
        sys.exit(-1)

    st = u.getpathtype(srcobj)
    if st == u.UNKNOWN:
        print("Unknown source path!")
        sys.exit()

    configs = []
    if st == u.IS_DIR:
        for f in os.listdir(srcobj):
            fp = os.path.join(srcobj, f)
            if os.path.isfile(fp) and os.path.basename(fp)[-5:] == ".conf":
                configs.append(fp)
    if st == u.IS_FILE:
        configs.append(srcobj)

    configs.sort()

    for c in configs:
        print("Parsing Comodo config: %s" % c)
        cname = os.path.basename(c)
        dname = cname.replace(".conf", ".json")

        try:
            with open(c) as file:
                data = file.read()
        except:
            print("Exception catched - ", sys.exc_info())
            sys.exit(-1)

        try:
            mparser = msc_pyparser.MSCParser()
            mparser.lexer.default_secrule_variables.append("HTTP_User-Agent")
            mparser.lexer.default_secrule_variables.append("HTTP_REFERER")
            mparser.lexer.default_config_simple_directives.append("<LocationMatch /options-general\.php>")
            mparser.lexer.default_config_simple_directives.append("<LocationMatch /sql\.php>")
            mparser.lexer.default_config_simple_directives.append("<LocationMatch /lib/exe/ajax\.php>")
            mparser.lexer.default_config_simple_directives.append("<LocationMatch /export\.php>")
            mparser.lexer.default_config_simple_directives.append("</LocationMatch>")

            mparser.add_comment = lambda x: \
                empty()

            old_append_action = mparser.append_action


            def append_action(act):
                if mparser.secconfdir == "secrule":
                    act_arg = act['act_arg']
                    match act['act_name']:
                        case "chain":
                            mparser.secrule['chained'] = True
                        case "tag":
                            match = re.match("paranoia-level/(\d)", act_arg)
                            if match:
                                level = match.group(1)
                                mparser.secrule['paranoia_level'] = int(level)
                        case "id":
                            mparser.secrule['id'] = act_arg
                        case "phase":
                            mparser.secrule['phase'] = act_arg
                        case "skipAfter":
                            mparser.secrule['skip_after'] = act_arg
                        case 'nolog':
                            if mparser.secrule.get('opts') is not None:
                                mparser.secrule['opts']['nolog'] = 1
                            else:
                                mparser.secrule['opts'] = {'nolog': 1}
                        case _:
                            mparser.secrule['actions'].append(act)
                    operator = mparser.secrule.get('operator')
                    operator_argument = mparser.secrule.get('operator_argument')
                    if (operator and expand_operators.get(operator) is not None) \
                            or (operator_argument and re.match("%{([^}]+)}", operator_argument)):
                        if mparser.secrule.get('opts') is not None:
                            mparser.secrule['opts']['parsepattern'] = 1
                        else:
                            mparser.secrule['opts'] = {'parsepattern': 1}
                if mparser.secconfdir == "secaction":
                    mparser.secaction['actions'].append(act)


            mparser.append_action = append_action
            mparser.parser.parse(data)
        except:
            print(sys.exc_info()[1])
            sys.exit(-1)

        o = os.path.join(dstobj, dname)
        try:
            with open(o, "w") as file:
                json.dump(mparser.configlines, file, indent=4, sort_keys=True)
        except:
            print("Exception catched - ", sys.exc_info())
            sys.exit(-1)

#!/usr/bin/env python

import datetime
import re
import sys

from tools import *


LOG_FILE = sys.argv[1]

# options

opt_parse_ts = 1

opt_parse_fourtuple = 1



# preparation

if opt_parse_fourtuple:
    pattern = re.compile("\d{1,10}_\d{1,10}_\d{1,10}_\d{1,10}")


f = open(LOG_FILE, 'r')

for line in f:
    line = line[:-1]

    try:
    
        if opt_parse_ts:
            ts, line = line.split(' ', 1)
            ts = float(ts)
            dt_str = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            line = dt_str + ' ' + line
    
        if opt_parse_fourtuple:
            m = pattern.search(line)
            if m:
                a, b = pattern.split(line, 1)
                sip, sport, dip, dport = parse_4tuple(m.group(0))
                sport = str(sport)
                dport = str(dport)
                line = a + sip + '_' + sport + '_' + dip + '_' + dport + b

        print(line)

    except Exception as ex:
        #print(line, file=sys.stderr)
        sys.stderr.write(line + '\n')
        #print(line)
        raise ex

f.close()




#!/usr/bin/env python

import os
from time import sleep


INNER_WEBSITES = {
    'vps': 'http://202.112.50.150/ultrasurf',
}

TARGETS = INNER_WEBSITES


def test_websites():
    i = 0
    while True:
        i += 1
        print("[Round %d]" % i)
        for website, url in TARGETS.iteritems():
            print("Testing website %s..." % website) 
            os.system("wget -q -O /dev/null --tries=1 --timeout=5 \"%s\"" % url)
            sleep(5)


if __name__ == "__main__":
    test_websites()


#!/usr/bin/env python


import urllib2

content = urllib2.urlopen("http://sspai.com/ultrasurf").read()
print(content)



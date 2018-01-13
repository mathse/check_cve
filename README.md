# universal CVE check for check_mk

## usage

place check.py into /usr/lib/check_mk_agent/local or /usr/lib/check_mk_agent/local/3600 (or any other subfolder)
place cve directory into /usr/lib/check_mk_agent/

the check will produce one single check with all checked json 50x_files

## example

2017-5754.json will check the installed kernel against a known (good) version which is not vulnerable against meltdown

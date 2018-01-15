#!/usr/bin/python
# ref: https://stackoverflow.com/questions/11887762/compare-version-strings-in-python

import glob, os, json
from distutils.version import LooseVersion

dir = "/usr/lib/check_mk_agent/cve"

osname = os.popen("PATH=$PATH:/opt/puppetlabs/bin; facter operatingsystem").read().replace("\n","")
osreleasemajor = os.popen("PATH=$PATH:/opt/puppetlabs/bin; facter operatingsystemmajrelease").read().replace("\n","")

# counter
affected = 0
known = 0
unknown = 0
msg_list = []

# loop cve's
os.chdir(dir)
for cve_file in glob.glob("*.json"):
    cve_data = json.load(open("%s/%s" % (dir, cve_file)))
    cve = cve_file.replace(".json","")
    cve_name = cve_data['name']
    cve_type = cve_data['type']

    if cve_type == 'script':
        cve_script = cve_data['script']
        known += 1
        if int(os.popen(cve_script).read().replace("\n","")) != 0:
            affected += 1
            msg_list.append("system is affected by %s (%s)" % (cve_name, cve))

    if cve_type == 'package':
        try:
            cve_info = cve_data['os'][osname]['info_url']
            cve_query = cve_data['os'][osname]['query_command']
            cve_package_name = cve_data['os'][osname]['package_name']
            cve_fixed_version = cve_data['os'][osname]['versions'][osreleasemajor]['fixed_version']
            current_version = os.popen(cve_query % cve_package_name).read().replace("\n","")
            known += 1
            if current_version:
                if LooseVersion(current_version) < LooseVersion(cve_fixed_version):
                    affected += 1
                    msg_list.append("system is affected by %s (%s) - please patch %s (more info %s)" % (cve_name, cve, cve_package_name, cve_info))
        except:
            unknown += 1
            msg_list.append("no definition found for %s and %s (%s)" % (osname, cve_name, cve))


if affected > 0:
    exit_code = 2
    exit_status = "CRIT"
else:
    exit_code = 0
    exit_status = "OK"

if unknown > 0:
    exit_code = 1
    exit_status = "WARN"

if len(msg_list) == 0:
    msg_list.append("system looks fine - 0 of %s cve's affected" % known)

print "%s check_cve known=%s|unknown=%s|affected=%s %s - %s" % (exit_code, known, unknown, affected, exit_status, ", ".join(msg_list))

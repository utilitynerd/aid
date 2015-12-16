from setuptools import  setup, find_packages
import sys

# If python2, install ipaddress package
python2_reqs = ""
if sys.version_info[0] == 2:
    python2_reqs = "ipaddress"

setup(
    name='aid',
    version='0.0.3',
    url='',
    license='Copyright UC Regents',
    author='Mike Jones',
    author_email='mikejones@security.berkeley.edu',
    description='library and scripts for interacting with ISP AID list',
    include_package_data=True,
    packages=find_packages(),
    install_requires=[
        'requests',
        'dateparser',
        python2_reqs,
    ],
    extras_require={
        'iptables': ["Click", "python-iptables"]
    },
    entry_points={
        "console_scripts" : [
            'aid-iptables=aid.iptables:generate_aid_list [iptables]'
        ],
    }
)

from setuptools import  setup, find_packages
import sys


# If python2, install ipaddress package
python2_reqs = ""
if sys.version_info[0] == 2:
    python2_reqs = "ipaddress"

setup(
    name='aid',
    version='0.1.2',
    url='https://github.com/utilitynerd/aid',
    license='Educational Community License, Version 2.0',
    author='Mike Jones',
    author_email='mikejones@security.berkeley.edu',
    description='library and scripts for interacting with ISP AID list',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Networking :: Firewalls',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],
    include_package_data=True,
    packages=find_packages(),
    install_requires=[
        'requests',
        'dateparser',
        'click',
        'convertdate<=2.0.7',
        python2_reqs,
    ],
    extras_require={
        'iptables': ["python-iptables"]
    },
    entry_points={
        "console_scripts": [
            'aid-list=aid.cli:cli',
        ],
    }
)

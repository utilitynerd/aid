from setuptools import  setup, find_packages


setup(
    name='aid',
    version='0.0.1.dev3',
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

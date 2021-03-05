import os
import sys

from setuptools import find_packages
from setuptools import setup

version = '0.9.0.dev0'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'pystackpath>=0.5.0,<1.0.0',
    'setuptools>=39.0.1',
    'zope.interface',
    'requests',
    'acme>=0.31.0',
    'certbot>=1.1.0',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

setup(
    name='certbot-dns-stackpath',
    version=version,
    description="StackPath DNS Authenticator plugin for Certbot",
    url='https://github.com/fxa90id/certbot-dns-stackpath',
    author="fxa90id",
    author_email='fxa90id@pm.me',
    license='Apache License 2.0',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        'certbot.plugins': [
            'dns-stackpath = certbot_dns_stackpath._internal.dns_stackpath:Authenticator',
        ],
    },
)

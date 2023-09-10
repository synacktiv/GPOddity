# -*- coding: utf-8 -*-
from setuptools import setup, find_packages


setup(
    name='GPOddity',
    version="1.0",
    author="Quentin Roland",
    author_email="quentin.roland@synacktiv.com",
    install_requires=["impacket","typer[all]"],
    description="The GPOddity project, aiming at automating GPO attack vectors through NTLM relaying (and more).",
    include_package_data=True,
    url='https://github.com/synacktiv/GPOddity',
    packages=['helpers', 'cleaning'],
    py_modules=['gpoddity', 'conf'],
    entry_points = {
        'console_scripts': [
            'gpoddity = gpoddity:entrypoint',
        ]
    },
    classifiers=[
        "Programming Language :: Python",
    ],
)

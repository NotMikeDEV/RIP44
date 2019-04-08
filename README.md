# RIP44

This is a RIP44 daemon for AMPRNet Only. If you don't have a 44/8 allocation and have no idea what that means then this project is of no use to you!

## Usage

I have provided an OpenWRT package in this repository for easy install on OpenWRT devices. Just download and install the .ipk file to install. Other operating systems should use the rip44.lua script along with the rip44.conf file.

Once installed, edit /etc/rip44.conf to specify your local prefix and reboot.

Further information at http://wiki.ampr.org/wiki/RIP44.lua

## Building Packages

You should be able to build the OpenWRT package by adding https://github.com/NotMikeDEV/RIP44.git to your feeds.conf and following the instructions on the OpenWRT wiki.
#!/bin/bash

# Find Distro
source /etc/os-release
distro=$(echo $PRETTY_NAME | awk 'FS=" " {print $1;}')

apt-get update 

# Dependencies
dependencies="python3 \
               python3-tk"

# Install dependencies, packages
apt-get -y install $dependencies
pip3 install pyshark

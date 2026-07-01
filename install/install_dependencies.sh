#!/bin/sh

sudo apt update
set -e

# Dependencies
dependencies="python3 \
    python3-pip \
    python3-tk \
    tshark \
    git"

# Required python packages
python_packages="pycrate \
    pyshark"

# Install dependencies, packages
sudo DEBIAN_FRONTEND=noninteractive apt install -y $dependencies
python3 -m pip install -r requirements.txt

# Install j2735_202409 package if not already installed
if python3 -c "import j2735_202409" 2>/dev/null; then
    echo "j2735_202409 is already installed, skipping."
else
    echo "Installing j2735_202409..."
    git clone https://github.com/usdot-fhwa-stol/j2735_202409.git
    cd j2735_202409
    python3 -m pip install dist/j2735_202409-0.1.0-py3-none-any.whl
    cd ..
    rm -rf j2735_202409
fi

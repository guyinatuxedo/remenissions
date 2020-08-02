#!/bin/bash

#GHIDRA_DIR="/tools/ghidra/ghidra_9.1.2_PUBLIC"
GHIDRA_DIR="/tools/ghidra/ghidra_9.1.2_PUBLIC"

if ! [[ -d $GHIDRA_DIR ]]
then
	echo "Set Ghidra Dir to your Ghidra directory"
	exit
fi

echo "Installing Remenissions"

sudo apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential gem ruby openjdk-11-jdk openjdk-11-jre-headless

# Install python libraries
sudo pip3 install zstandard setuptools

# Install one_gadget
sudo gem install one_gadget

# Install Itl
cd dependencies/itl/
sudo ./install
cd ../../

# Install The Night
cd dependencies/The_Night/
python3 download.py
sudo python3 setup.py install
cd ../../

# Install sf
cd dependencies/sf/
sudo python3 setup.py install
cd ../../

# This line is from stack overflow
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Install gdb-gef/far_away
echo source $DIR/far_away.py >> ~/.gdbinit
echo source $DIR/dependencies/gef/.gdbinit-gef.py >> ~/.gdbinit

#Install pwntools
sudo apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install --upgrade pwntools

# Install death stranding
cp static_analyzer/death_stranding.py $GHIDRA_DIR/Ghidra/Features/Python/ghidra_scripts/death_stranding.py

# Make remenissions symbolic link
sudo ln -s $DIR/remenissions /usr/bin/remenissions

# Write the install directories
sed -i 's\INSTALL_DIR = "/Hackery/remenissions/"\INSTALL_DIR = "'$DIR'/"\g' remenissions
sed -i 's\INSTALL_DIR = "/Hackery/remenissions/"\INSTALL_DIR = "'$DIR'/"\g' solway_firth.py

# Write the ghidra headless analyzer directory
sed -i 's\HEADLESS_GHIDRA_DIR = "/tools/ghidra/ghidra_9.1.2_PUBLIC/support/"\HEADLESS_GHIDRA_DIR = "'$GHIDRA_DIR'/support/"\g' remenissions


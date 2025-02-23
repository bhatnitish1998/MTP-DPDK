#!/bin/bash

cd ../../usertools
sudo python3 dpdk-devbind.py --bind=vfio-pci ens19f0np0
cd ~/nitish/MTP/setup_scripts
sudo ./huge_pages.sh

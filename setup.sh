#!/bin/bash

cd ../../usertools
sudo python3 dpdk-devbind.py --bind=vfio-pci ens19f0np0
cd /home/magnus/nitish/MTP/setup_scripts
sudo ./huge_pages.sh

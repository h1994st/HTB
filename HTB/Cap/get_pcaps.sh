#!/bin/bash

dest_dir="pcaps"
# Check if the destination directory exists, if not create it
if [ ! -d "$dest_dir" ]; then
    mkdir "$dest_dir"
fi

# This script is used to get the pcap files from the HTB Cap challenge
for ((i=0; i<=23; i++))
do
    wget -O "${dest_dir}/${i}.pcap" "http://10.10.10.245/download/${i}"
done

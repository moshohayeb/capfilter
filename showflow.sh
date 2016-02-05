#!/bin/sh

flow=$1
dir=./dbg

flowdir=`find $dir -name *$flow*`

cat $flowdir/events.txt
cat $flowdir/raw.json
open -a wireshark $flowdir/dump.pcap

#!/bin/bash

set -ev

go test github.com/andrewbytecoder/gopacket
go test github.com/andrewbytecoder/gopacket/layers
go test github.com/andrewbytecoder/gopacket/tcpassembly
go test github.com/andrewbytecoder/gopacket/reassembly
go test github.com/andrewbytecoder/gopacket/pcapgo
go test github.com/andrewbytecoder/gopacket/pcap
sudo $(which go) test github.com/andrewbytecoder/gopacket/routing

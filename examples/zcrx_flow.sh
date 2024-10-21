#!/bin/bash

ethtool -N eth0 delete 0
ethtool -X eth0 context 1 delete

ethtool -L eth0 combined 64
ethtool -X eth0 equal 12

ethtool -X eth0 context new start 12 equal 1
ethtool -N eth0 flow-type tcp6 dst-port 9999 context 1

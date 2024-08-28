#! /usr/bin/env bash

function clean_namespaces {
	ip netns del nscl
	ip netns del nsserv
	ip link del ptp-serv
	echo 10
}
trap clean_namespaces EXIT

ip link add ptp-cl type veth peer name ptp-serv

ip netns add nscl
ip link set ptp-cl netns nscl
ip netns exec nscl ip addr add '10.10.10.10/24' dev ptp-cl
ip netns exec nscl ethtool -K ptp-cl tcp-segmentation-offload off
ip netns exec nscl ethtool -K ptp-cl generic-receive-offload on
ip netns exec nscl ip link set dev ptp-cl up

ip netns add nsserv
ip link set ptp-serv netns nsserv
ip netns exec nsserv ip addr add '10.10.10.20/24' dev ptp-serv
ip netns exec nsserv ethtool -K ptp-serv tcp-segmentation-offload off
ip netns exec nsserv ethtool -K ptp-serv generic-receive-offload on
ip netns exec nsserv ip link set dev ptp-serv up

ip netns exec nsserv ./prog 1 &
ip netns exec nscl ./prog 0

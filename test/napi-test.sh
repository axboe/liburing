#! /usr/bin/env bash

if [ ! -x "$(command -v ip)" ]; then
	echo "Need ip installed"
	exit 77
fi
if [ ! -x "$(command -v ethtool)" ]; then
	echo "Need ethool installed"
	exit 77
fi

function clean_namespaces {
	ip netns del nscl
	ip netns del nsserv
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

# test basic init, defer_taskrun, and sqpoll
QUEUE_FLAGS="0x0 0x3000 0x2"
for flags in $QUEUE_FLAGS; do
	if [ -f "napi-test.t" ]; then
		NAPI_TEST="./napi-test.t"
	elif [ -f "test/napi-test.t" ]; then
		NAPI_TEST="test/napi-test.t"
	else
		echo "Can't find napi-test.t"
		exit 77
	fi
	ip netns exec nsserv $NAPI_TEST receive $flags &
	ip netns exec nscl $NAPI_TEST send $flags
	wait
done

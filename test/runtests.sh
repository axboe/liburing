#!/bin/bash

TESTS="$@"
RET=0

TIMEOUT=30
FAILED=""
MAYBE_FAILED=""

do_kmsg="yes"
if ! [ $(id -u) = 0 ]; then
	do_kmsg="no"
fi

TEST_DIR=$(dirname $0)
TEST_FILES=""
if [ -f "$TEST_DIR/config.local" ]; then
	. $TEST_DIR/config.local
	for dev in $TEST_FILES; do
		if [ ! -e "$dev" ]; then
			echo "Test file $dev not valid"
			exit 1
		fi
	done
fi

run_test()
{
	T="$1"
	D="$2"
	if [ "$do_kmsg" = "yes" ]; then
		echo Running test $T $D | tee /dev/kmsg
	else
		echo Running test $T $D
	fi
	timeout --preserve-status -s INT $TIMEOUT ./$T $D
	r=$?
	if [ "${r}" -eq 124 ]; then
		echo "Test $T timed out (may not be a failure)"
	elif [ "${r}" -ne 0 ]; then
		echo "Test $T failed with ret ${r}"
		FAILED="$FAILED <$T $D>"
		RET=1
	elif [ ! -z "$D" ]; then
		sleep .1
		ps aux | grep "\[io_wq_manager\]" > /dev/null
		R="$?"
		if [ "$R" -eq 0 ]; then
			MAYBE_FAILED="$MAYBE_FAILED $T"
		fi
	fi
}

for t in $TESTS; do
	run_test $t
	if [ ! -z "$TEST_FILES" ]; then
		for dev in $TEST_FILES; do
			run_test $t $dev
		done
	fi
done

if [ "${RET}" -ne 0 ]; then
	echo "Tests $FAILED failed"
	exit $RET
else
	sleep 1
	ps aux | grep "\[io_wq_manager\]" > /dev/null
	R="$?"
	if [ "$R" -ne 0 ]; then
		MAYBE_FAILED=""
	fi
	if [ ! -z "$MAYBE_FAILED" ]; then
		echo "Tests _maybe_ failed: $MAYBE_FAILED"
	fi
	echo "All tests passed"
	exit 0
fi

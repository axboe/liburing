#!/bin/bash

TESTS="$@"
RET=0

TIMEOUT=10
FAILED=""

for t in $TESTS; do
	echo Running test $t
	timeout -s INT $TIMEOUT ./$t
	r=$?
	if [ "${r}" -eq 124 ]; then
		echo "Test $t timed out (may not be a failure)"
	elif [ "${r}" -ne 0 ]; then
		echo Test $t failed
		FAILED="$FAILED $t"
		RET=1
	fi
done

if [ "${RET}" -ne 0 ]; then
	echo "Tests $FAILED failed"
fi

exit $RET

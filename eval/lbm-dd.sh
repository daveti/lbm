#!/bin/bash
set -ue

if [ $# -lt 1 ]; then
	echo "usage: $0 output_file"
	exit 1
fi

INPUT_FILE=/dev/zero
OUTPUT_FILE=$1
COUNT=10000
RUNS=5

run_dd() {
	output=$(dd if=$INPUT_FILE oflag=direct of=$OUTPUT_FILE count=$COUNT bs=$(mult $1 1024) 2>&1)
	# 851050496 bytes (851 MB, 812 MiB) copied, 6.44626 s, 132 MB/s
	mbs=$(echo "$output" | egrep -o '[0-9.]+ MB/s$' | egrep -o '[0-9.]+')
	time=$(echo "$output" | egrep -o '[0-9.]+ s,' | egrep -o '[0-9.]+')
}

add() {
	result=$(echo -e "$1\n$2" | awk '{ total += $1; } END { print "" total }')
	echo $result
}

div() {
	result=$(echo "$1 $2" | awk '{ print "" $1/$2 }')
	echo $result
}

mult() {
	result=$(echo "$1 $2" | awk '{ print "" $1*$2 }')
	echo $result
}

echo '----- dd benchmark -----'
echo
echo 'Input file:' $INPUT_FILE
echo 'Output file:' $OUTPUT_FILE
echo 'Block count:' $COUNT
echo 'Machine:' $(uname -a)
echo 'Mount:' $(mount | grep $(dirname $OUTPUT_FILE))
echo 'Started' $(date)
echo

# warm up the drive first
run_dd 4

total_time=0.0
for i in 4 8 16 32 64 128; do
	average=0.0

	for run in $(seq 1 $RUNS); do
		run_dd $i
		echo "run $run: ${i}KB ($mbs MB/s in ${time} s)"
		total_time=$(add $total_time ${time})
		average=$(add $average $mbs)
	done
	echo "average: $(div $average $RUNS) MB/s"
	echo
done

echo "Eval took $total_time seconds"

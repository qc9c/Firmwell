#!/bin/bash

TARGET_FOLDER=${1}
OUTFILE="targets.list.`basename ${1}`"
# Maximum number of parallel processes
MAX_PROCESSES=$(nproc)

echo "Generating $OUTFILE for targets in $TARGET_FOLDER..."
if [[ -f $OUTFILE ]]; then
	echo "    removing old $OUTFILE"
	rm $OUTFILE
fi

touch $OUTFILE

# Create a temporary directory for hash results
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

BRAND=`basename ${1}`
echo "    processing $BRAND"

# Get the list of targets in the original order
TARGETS=($(ls $TARGET_FOLDER))

# Calculate hashes in parallel
for TARGET in "${TARGETS[@]}"; do
	TARGETPATH=$TARGET_FOLDER/$TARGET
	NAME="${TARGET%.*}"
	# Start a background process to calculate the hash
	(
		HASH=$(sha256sum "$TARGETPATH" | cut -d ' ' -f 1)
		echo "$HASH" > "$TEMP_DIR/$TARGET"
	) &

	# Limit number of parallel processes
	if [[ $(jobs -r -p | wc -l) -ge $MAX_PROCESSES ]]; then
		wait -n
	fi
done

# Wait for all background processes to complete
wait

# Write results to the output file in the original order
for TARGET in "${TARGETS[@]}"; do
	TARGETPATH=$TARGET_FOLDER/$TARGET
	NAME="${TARGET%.*}"
	HASH=$(cat "$TEMP_DIR/$TARGET")
	echo $BRAND,$NAME,$TARGETPATH,$HASH >> $OUTFILE
done

echo $OUTFILE "done"
echo "target.list num:" $(cat $OUTFILE | wc -l)

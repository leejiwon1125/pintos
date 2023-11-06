#!/bin/bash

# Path to the directory containing the test result files
TEST_RESULT_DIR="./test_result_dir"

# Counter for passed test batches
passed_count=0

# Loop through all test result files
for ((i=1; i<=26; i++))
do
  # Check if the "All 80 tests passed." line is in the test result file
  if grep -q "All 80 tests passed." "$TEST_RESULT_DIR/test_$i.txt"; then
    # Increment the passed counter if the line is found
    ((passed_count++))
  else
    # Print which test batch failed
    echo "Test batch $i did not pass all tests."
  fi
done

# Check if all test batches passed
if [ $passed_count -eq 26 ]; then
  echo "All 100 test batches passed."
else
  echo "Some test batches did not pass."
  echo "Passed test batches: $passed_count"
fi

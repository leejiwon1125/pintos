#!/bin/bash


# Check if test_result_dir exists, if not create it
if [ ! -d "test_result_dir" ]; then
  mkdir test_result_dir
fi

# Perform the test process 100 times
for ((i=1; i<=100; i++))
do
  # Run make
  make

  # Run make check and redirect output to a file, incrementing the file name each time
  make check > "./test_result_dir/test_$i.txt"

  # Clean up
  make clean
done

# Navigate out of the userprog directory
cd ../../

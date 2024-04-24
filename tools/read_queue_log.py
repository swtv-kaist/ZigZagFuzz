import sys

if len(sys.argv) != 2:
  print("Usage: {} <queue_log_file>".format(sys.argv[0]))
  exit(1)


data = dict()
with open(sys.argv[1]) as f:
  f.readline()
  for line in f:
    line = line.strip().split(":")
    argv_id = int(line[2])
    num_fuzzed = int(line[4])
    disabled = int(line[6])

    if argv_id not in data:
      data[argv_id] = dict()
      data[argv_id]["num_tcs"] = 0
      data[argv_id]["num_fuzzed"] = 0

    data[argv_id]["num_tcs"] += 1
    data[argv_id]["num_fuzzed"] += num_fuzzed
    data[argv_id]["disabled"] = disabled

num_tc_one_argvs = 0
num_total_fuzzed = 0
num_fuzzed_zero_argvs = 0
num_disabled = 0
for argv_id in data:
  if data[argv_id]["num_tcs"] == 1:
    num_tc_one_argvs += 1
  num_total_fuzzed += data[argv_id]["num_fuzzed"]
  if data[argv_id]["num_fuzzed"] == 0:
    num_fuzzed_zero_argvs += 1
  
  if data[argv_id]["disabled"] == 1:
    num_disabled += 1
  


print("Number of argvs: {}".format(len(data)))
print("Number of argvs with only one testcase: {}".format(num_tc_one_argvs))
print("Number of argvs with no fuzzed testcase: {}".format(num_fuzzed_zero_argvs))
print("Number of total fuzzed testcases: {}".format(num_total_fuzzed))
print("Number of disabled argvs: {}".format(num_disabled))
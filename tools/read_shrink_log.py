import sys

f = open(sys.argv[1], "r")

result = []
shrink_index = -1
select_batch = None
for line in f:
  if "Shrink #" in line:
    assert(shrink_index + 1 == int(line.strip().split(",")[0].split("#")[1]))
    shrink_index += 1
    result.append(dict())
    num_tcs = int(line.strip().split("/")[-1].split(",")[0])
    num_active_tcs = int(line.strip().split("/")[-2].split(",")[-1])
    result[shrink_index]["num_tcs"] = num_tcs
    result[shrink_index]["num_active_tcs"] = num_active_tcs

    if len(result) > 1:
      result[shrink_index -1]["num_argv_reduced"] = len(select_batch)
      num_queue_sum = 0
      for argv_id in select_batch:
        num_queue_sum += select_batch[argv_id]

    select_batch = dict()

  elif "SHRINK: Selected " in line:
    argv_id = int(line.strip().split(", ")[2].split(" ")[-1])
    num_queue = int(line.strip().split(", ")[-1].split(" ")[-1])
    select_batch[argv_id] = num_queue

if select_batch is None:
  print("No shrink logs")
  exit()

result[shrink_index]["num_argv_reduced"] = len(select_batch)
num_queue_sum = 0
for argv_id in select_batch:
  num_queue_sum += select_batch[argv_id]
  

idx = 0
for shrink_res in result:
  print("{} : num_tcs : {}, num_active_tcs : {}, num_argv_reduced: {}".format(idx, shrink_res["num_tcs"], shrink_res["num_active_tcs"], shrink_res["num_argv_reduced"]))
  idx += 1


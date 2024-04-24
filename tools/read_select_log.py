import sys

f = open(sys.argv[1], "r")

argv_data = dict()
for line in f:
  if "Selected" in line:
    line = line.strip().split(",")
    queue_id = int(line[0].split(" ")[1])
    argv_id = int(line[1].split(" ")[-1])

    if argv_id not in argv_data:
      argv_data[argv_id] = dict()
      argv_data[argv_id]["num_select"] = 0
      argv_data[argv_id]["num_found"] = 0
      argv_data[argv_id]["num_try"] = 0
    
    argv_data[argv_id]["num_select"] += 1
  else:
    line = line.strip().split(" ")
    argv_data[argv_id]["num_found"] += int(line[0].split("/")[0])
    argv_data[argv_id]["num_try"] += int(line[0].split("/")[1])


result = []
for argv_id in argv_data:
  result.append("{} : {}/{}/{}".format(argv_id, argv_data[argv_id]["num_select"], argv_data[argv_id]["num_found"], argv_data[argv_id]["num_try"]))

def sort_fn(key):
  key = key.split(" : ")
  founds = key[1].split("/")

  return int(founds[1]) * 10000 + int(founds[0]) * 100 + int(key[0])

result.sort(key=sort_fn, reverse=True)
for res in result:
  print(res)

print("{} argvs selected".format(len(argv_data)))
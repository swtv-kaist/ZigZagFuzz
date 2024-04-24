import glob
import sys

if len(sys.argv) != 2:
  print("usage : {} <queue_dir>".format(sys.argv[0]))
  exit()

queue_dir = sys.argv[1]

fns = glob.glob("{}/id:*".format(queue_dir))
print("# of files : {}".format(len(fns)))

files = dict()
for fn in fns:
  with open(fn, "rb") as f1:
    file_conts = f1.read()

    if file_conts not in files:
      files[file_conts] = 0
    
    files[file_conts] += 1

#print(argvs)
#print("")

num_one_tcs = 0
print("# of tcs : {}".format(len(fns)))
print("# of argvs : {}".format(len(files)))

num_tcs_list = []
for file_conts in files:
  num_tcs = files[file_conts]
  num_tcs_list.append(num_tcs)

num_tcs_list.sort(reverse=True)
print(num_tcs_list)
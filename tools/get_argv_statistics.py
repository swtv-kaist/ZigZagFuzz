import glob
import sys

if len(sys.argv) != 2:
  print("usage : {} <queue_argv_dir>".format(sys.argv[0]))
  exit()



queue_argv_dir = sys.argv[1]


fns = glob.glob("{}/id:*".format(queue_argv_dir))
print("# of files : {}".format(len(fns)))

argvs = dict()
for fn in fns:
  with open(fn, "rb") as f1:
    argv = f1.read()

    while b'\0' in argv:
      argv = argv.replace(b'\0', b' ')
    
    argv = argv[:-2]

    if argv not in argvs:
      argvs[argv] = 0
    
    argvs[argv] += 1

#print(argvs)
#print("")

num_one_tcs = 0
print("# of tcs : {}".format(len(fns)))
print("# of argvs : {}".format(len(argvs)))

num_tcs_list = []
for argv in argvs:
  num_tcs = argvs[argv]
  if num_tcs == 1:
    num_one_tcs += 1
  else:
    num_tcs_list.append(num_tcs)
  if num_tcs >= 100:
    print("{} : {}".format(argv, num_tcs))

num_tcs_list.sort(reverse=True)
print(num_tcs_list)

print("# of one tcs : {}".format(num_one_tcs))

len_sum = 0
word_sum = 0
for argv in argvs:
  len_sum += len(argv)
  word_sum += len(argv.split(b" "))

if len(argvs) != 0:
  print("Avg len : {}, Avg # of word : {}".format(len_sum / len(argvs), word_sum / len(argvs)))

import sys
import glob

if len(sys.argv) != 2:
  print("usage : {} <queue_argv_dir>".format(sys.argv[0]))
  exit()


queue_argv_dir = sys.argv[1]


fns = glob.glob("{}/id:*".format(queue_argv_dir))
print("# of files : {}".format(len(fns)))
for fn in fns:
  with open(fn, "rb") as f1:
    argv = f1.read()
    if len(argv) >= 256:
      print("argv length is too long : {}".format(fn))



import sys, glob

COPY_IDX = list(range(1453))

if len(sys.argv) != 3:
    print('Usage: python copy_res.py <source> <destination>')
    sys.exit(1)

src = sys.argv[1]
dst = sys.argv[2]



import os
import shutil

shutil.rmtree(dst, ignore_errors=True)
os.mkdir(dst)
os.mkdir("{}/queue".format(dst))
os.mkdir("{}/queue_argvs".format(dst))


for i in COPY_IDX:
  src_file1 = glob.glob("{}/queue/id:{:06d},*".format(src, i))
  if len(src_file1) < 0:
    print("Error: {} not found".format(i))
    sys.exit(1)
  
  if len(src_file1) > 1:
    print("Error: {} found multiple files".format(src_file1))
    sys.exit(1)
  
  src_file1 = src_file1[0]

  shutil.copyfile(src_file1, "{}/queue/{}".format(dst, os.path.basename(src_file1)))

  src_file2 = glob.glob("{}/queue_argvs/id:{:06d}".format(src, i))
  if len(src_file2) < 0:
    print("Error: {} not found".format(i))
    sys.exit(1)
  
  if len(src_file2) > 1:
    print("Error: {} found multiple files".format(src_file2))
    sys.exit(1)
  
  src_file2 = src_file2[0]

  shutil.copyfile(src_file2, "{}/queue_argvs/{}".format(dst, os.path.basename(src_file2)))


  

from pathlib import Path
import sys, os
import subprocess as subp
import glob
import shutil
import multiprocessing


if len(sys.argv) != 5:
  print("usage : python3 {} <path/to/subject> <tcs> <timeout> <time_interval>".format(sys.argv[0]))
  exit()

# example : python3 get_gcov.py /home/cheong/gcov_subjects/ffmpeg/gcov_install/bin/ffmpeg /home/cheong/result/default/queue/ 3600 100

subject = sys.argv[1] # path/to/subject gcov executable
tcs = sys.argv[2]     # path to queue/
source_dir = "/".join(subject.split("/")[:-3])
TIMEOUT = int(sys.argv[3])
TIME_INTERVAL = int(sys.argv[4])

if source_dir[0] != "/":
  source_dir = os.getcwd() + "/" + source_dir

if tcs[0] != "/":
  tcs = os.getcwd() + "/" + tcs

if not os.path.exists(tcs):
  print("Error: {} does not exist".format(tcs))
  exit(1)

for p in Path(source_dir).rglob("*.gcda"):
  os.remove(p)
  
subject_name = subject.split("/")[-1]

tmp_argv_dir = "/".join(tcs.split("/")[:-1]) + "/tmp_argv"
shutil.rmtree(tmp_argv_dir, ignore_errors=True)
os.mkdir(tmp_argv_dir)

argv_queue_dir = "/".join(tcs.split("/")[:-1]) + "/queue_argvs"

argvs = []

plot_fn = tcs + "/../plot_data"

tc_id_list = []
with open(plot_fn, "r") as f1:
  f1.readline()
  cur_time_idx = 0
  last_path = 0
  for line in f1:
    line = line.strip().split(", ")
    try:
      cur_time = int(line[0])
      cur_path = int(line[3])
    except:
      break

    while (cur_time_idx * TIME_INTERVAL) < cur_time:
      tc_id_list.append(last_path)
      cur_time_idx += 1
    
    last_path = cur_path
    if cur_time > TIMEOUT:
      break

if cur_time_idx * TIME_INTERVAL < TIMEOUT * 0.95:
  print("Warn: unfinished job: {}, {:0.3}%".format(plot_fn, cur_time/TIMEOUT*100))
  exit(0)

while cur_time_idx < TIMEOUT / TIME_INTERVAL:
  tc_id_list.append(last_path)
  cur_time_idx += 1


cur_time_idx = 0
cur_tc_id = 0
idx = 0

num_total_tcs = cur_path

out_name = "{}.gcov".format("/".join(tcs.split("/")[:-2]))
out_f = open(out_name, "w")

mp_manager = multiprocessing.Manager()

num_timeout = multiprocessing.Value('i', 0)
timeouts = mp_manager.list()

def run_tc(tc_id, num_timeout, timeouts):
  tc_fn_str = tcs + "/id:" + '0'* (6 - len(str(tc_id))) + str(tc_id) + "*"
  tc_fns = glob.glob(tc_fn_str)

  tc_fn = None
  if len(tc_fns) == 1:
    tc_fn = tc_fns[0]
  elif len(tc_fns) == 0:
    return
  else:
    for fn in tc_fns:
      try:
        fn.encode()
      except:
        continue
      tc_fn = fn
      break
  
  if tc_fn is None:
    return

  argv_fn = argv_queue_dir + "/id:" + '0'* (6 - len(str(tc_id))) + str(tc_id)
  with open(argv_fn, "rb") as f2:
    argv = f2.read()
    placeholder_loc = argv.find(b"@@")
    if placeholder_loc != -1:
      argv = argv[:placeholder_loc] + tc_fn.encode() + argv[placeholder_loc + 2:]

  tmp_fn = tmp_argv_dir + "/id:" + '0'* (6 - len(str(tc_id))) + str(tc_id)
  with open(tmp_fn, "wb") as f2:
    f2.write(argv)

  cmd = [subject, tmp_fn]

  try:
    subp.run(cmd, stdout=subp.DEVNULL, stderr=subp.DEVNULL, stdin=subp.DEVNULL, timeout=0.8)
  except subp.TimeoutExpired:
    num_timeout.value += 1
    timeouts.append(tmp_fn)
  except:
    pass
    

num_cov_br = "0"
for last_tc_id in tc_id_list:
  running_process = set()

  for tc_id in range(cur_tc_id, last_tc_id):

    p = multiprocessing.Process(target = run_tc, args = (tc_id, num_timeout, timeouts))
    p.start()

    running_process.add(p)

    if len(running_process) >= 20:
      for p in running_process:
        p.join()
      running_process = set()
  
  for p in running_process:
    p.join()

  cur_tc_id = last_tc_id

  cmd = ["gcovr", "-b", "-s", "-r", source_dir]
  out = subp.run(cmd, stdout=subp.PIPE, stderr=subp.DEVNULL).stdout.decode()

  found_result = False
  for line in out.split("\n"):
    if "branches:" == line[:9]:
      num_cov_br = line.split("(")[1].split(" out")[0]
      out_f.write(num_cov_br + "\n")
      found_result = True
      break
  
  if not found_result:
    out_f.write(num_cov_br + "\n")
  
  print ("{} : {}/{} done".format(subject_name, cur_tc_id, num_total_tcs))

out_f.close()

if num_timeout.value != 0:
  print("num_timeout : {}: {}/{}".format(tcs, num_timeout.value, num_total_tcs))
  # for t in timeouts:
  #   print(t)

shutil.rmtree(tmp_argv_dir, ignore_errors=True)


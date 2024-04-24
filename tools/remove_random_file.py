import glob, sys, os, shutil

keep_list = ["subjects", "remove_random_file.py", "init_seed", "afl++" ,"result",
             "power", "utils", ".ssh", ".vim", "bash", "profile", "keyword", ".git",
             ".sudo_as_admin",
            ]

dry_run = 0
if len(sys.argv) == 2:
  if sys.argv[1] == "-d":
    dry_run = 1

out_list = ["@", ":", "%", "(", ")", ",", "[", "]", "#", "\\", "$"]

remove_list = []

for fn in glob.glob("./*") + glob.glob("./.*"):
  if fn[0] == "-":
    remove_list.append(fn)
    continue

  is_ban = 0
  for ban in out_list:
    if ban in fn:
      is_ban =1
      remove_list.append(fn)
      break

  if is_ban:
    continue

  try:
    fn.encode()
  except UnicodeEncodeError as e:
    remove_list.append(fn)
    continue

if dry_run:
  for fn in remove_list:
    print("Would remove {}".format(repr(fn)))
else:
  for fn in remove_list:
    print("removing {}".format(repr(fn)))
    try:
      os.remove(fn)
    except:
      pass
    try:
      shutil.rmtree(fn)
    except:
      pass
  

  


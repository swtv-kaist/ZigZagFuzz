
import subprocess as sp


cmd = ["ipcs", "-m"]
p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
out, err = p.communicate()
if p.returncode != 0:
  print("Error: {}".format(err))
  exit(1)

lines = out.decode().split("\n")
for line in lines:
  if not line.startswith("0x"):
    continue

  line = line.strip()
  while "  " in line:
    line = line.replace("  ", " ")
  
  line = line.split(" ")

  key = line[1]
  cmd = ["ipcrm", "-m", key]
  print(" ".join(cmd))
  p = sp.run(cmd)
  
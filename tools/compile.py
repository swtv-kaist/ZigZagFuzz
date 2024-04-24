import sys,os
import subprocess as sp
from pathlib import Path

if len(sys.argv) < 3:
  print("usage : {} <input.bc> <output> <compile args ...>")
  exit(0)

bc_fn = sys.argv[1]
output_fn = sys.argv[2]
compile_argvs = sys.argv[3:]

def check_given_bitcode(inputbc):
    # check given file exists
    if not os.path.isfile(inputbc):
        print("Can't find file : {}".format(inputbc))
        return False

    # check given file format
    cmd = ["file", inputbc]
    stdout = sp.run(cmd, stdout=sp.PIPE, stderr=sp.DEVNULL).stdout
    if b"bitcode" not in stdout:
        print("Can't recognize file : {}".format(inputbc))
        return False

    return True

if not check_given_bitcode(bc_fn):
  exit(1)

orig_filename = ".".join(bc_fn.split(".")[:-1])

cmd = ["ldd", orig_filename]

out = sp.run(cmd, stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode()

skip_list = [
  "libc.so", "linux-vdso.so", "libgcc_s.so", "ld-linux-x86-64.so", "libuuid",
  "libdbus-1.so", "libsystemd.so", "libwrap.so",
  "libsndfile.so", "libasyncns.so", "libapparmor.so", "liblz4.so", "libgcrypt.so",
  "libFLAC.so", "libogg.so", "libvorbis.so", "libvorbisenc.so", "libgpg-error.so",
  "libpulsecommon"
]

link_commands = []
is_cxx = False
for line in out.split("\n"):
  skip = False
  for skip_lib in skip_list:
    if skip_lib in line:
      skip = True
      break
  
  if skip:
    continue

  if "libstdc++" in line:
    is_cxx = True
    continue

  if "=>" not in line:
    continue

  line = line.strip().split("=>")[0]

  if "lib" not in line and "so" not in line:
    continue

  while "  " in line:
    line = line.replace("  ", " ")
  
  line = line.split("lib")[1].split(".so")[0]
  
  link_commands.append("-l" + line)

source_file_path = Path(__file__).resolve()
power_dir = str(source_file_path.parent.parent)

if is_cxx:
  cmd = ["{}/afl-clang-lto++".format(power_dir)]
else:
  cmd = ["{}/afl-clang-lto".format(power_dir)]

cmd += [bc_fn, "-o", output_fn] + link_commands + compile_argvs

print(" ".join(cmd))
sp.run(cmd)

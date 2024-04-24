

cmd = ["-f", "/home/cheong/init_seeds/jasper/testimgari.jpg",  "-T", "bmp", "-F", "/dev/null"]

f1 = open("tmp.txt", "wb")

for arg in cmd:
  f1.write(arg.encode() + bytes(1))

f1.write(bytes(2))

f1.close()

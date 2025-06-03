import sys
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
def main():
   if len(sys.argv) != 3:
       print("Usage: python raw_to_der.py raw_signature.bin output.der")
       sys.exit(1)
   raw_file = sys.argv[1]
   der_file = sys.argv[2]
   with open(raw_file, "rb") as f:
       raw = f.read()
   if len(raw) % 2 != 0:
       print("Invalid signature length, should be even (r||s)")
       sys.exit(1)
   half = len(raw) // 2
   r = int.from_bytes(raw[:half], byteorder="big")
   s = int.from_bytes(raw[half:], byteorder="big")
   der = encode_dss_signature(r, s)
   with open(der_file, "wb") as f:
       f.write(der)
   print("DER signature written to: %s" % der_file)
if __name__ == "__main__":
   main()

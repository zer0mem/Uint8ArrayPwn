#.load pykd.pyd; !py u8a

import sys
from pykd import *
   
def run():
   pass

def main():
   dprintln("" )
   dprintln("<link cmd=\"!py u8a\">u8a</link>", True)
   dprintln("")

   err = 0
   count = 0
   
   uInt8Array = dbgCommand("s -d 0 L?0x0FFFFFFF 0x48474545").split("\n")
   for hook in uInt8Array:
	try:
		print hook
		addr = int("0x" + hook.split(" ")[0].replace("`", ""), 16)
			
		subArrHeader = dbgCommand("s -d 0 L?0x0FFFFFFF 0x%x"%(addr)).split("\n")
			
		for hdr in subArrHeader:
			count += 1	
			hdrPtr = int("0x" + hdr.split(" ")[0].replace("`", ""), 16)
			
			try:
				#FF 11
				dbgCommand("ed 0x%x 0x%x"%(hdrPtr - 0x28, 0xFFFFFFFF))#byteLength
				dbgCommand("ed 0x%x 0x%x"%(hdrPtr - 0x38, 0xFFFFFFFF))#length !
				
				#chrome
				#dbgCommand("ed 0x%x 0x%x"%(hdrPtr - 0xC, 0xFFFFFFFF))#
				print hdr
			except:
				err += 1
			
	except:
		print "DOUBLE ERR : %s"%(hook)

   print "Count of owned SubArray - headers %i ! [%i]"%(count, err)
   
if __name__ == "__main__":
    main()

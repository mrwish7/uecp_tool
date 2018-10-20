import sys

ps = None
tatp = None
rt = None

class UECP_Frame_Decoder() :
	def __init__(self):
		self.message_begin_seen = False
		self.data = []
		self.next_escaped = False
		
	def add_byte(self, b) :
		if self.next_escaped:
			self.next_escaped = False
			if b == 0x00:
				self.data.append(0xFD)
			elif b == 0x01:
				self.data.append(0xFE)
			elif b == 0x02:
				self.data.append(0xFF)
				
		elif b == 0xFD and self.message_begin_seen:
			self.next_escaped = True
		
		elif b == 0xFE and not self.message_begin_seen:
			self.message_begin_seen = True
			self.data.append(b)
			
		elif b == 0xFF and self.message_begin_seen:
			self.data.append(b)
			self.decode_frame()
			return False
		
		elif self.message_begin_seen:
			self.data.append(b)
		
		return True
		
	def decode_frame(self) :
		self.addr = self.data[1] * 256 + self.data[2]
		self.sqc  = self.data[3]
		self.mfl  = self.data[4]
		self.msg  = self.data[5:5+self.mfl]
		UECP_Message_Decoder(self.msg)
		
class UECP_Message_Decoder():
	def __init__(self, message_bytes):
		global ps
		global tatp
		global rt
		self.message = message_bytes
		self.mec = message_bytes[0]
		
		if self.mec == 0x02 :
			ps = ''.join(chr(d) for d in self.message[3:])
			#print('PS: "' + ps + '"\n')
			sys.stdout.flush()
			sys.stdout.write('PS ' + ps + '\n')
		if self.mec == 0x03 :
			if (self.message[3] == 0x1) or (self.message[3] == 0x3) :
				sys.stdout.flush()
				sys.stdout.write('TA ON' + '\n')
			else :
				sys.stdout.flush()
				sys.stdout.write('TA OFF' + '\n')	
			#print('TA/TP: ' + hex(tatp) + '\n')
		if self.mec == 0x07 :
			pty = self.message[3]
			#print('PTY: ' + pty_table[hex(pty)] + '\n')
			sys.stdout.flush()
			sys.stdout.write('PTY ' + str(pty) + '\n')
		if self.mec == 0x0A :
			rt = ''.join(chr(d) for d in self.message[5:])
			sys.stdout.flush()
			sys.stdout.write('RT ' + rt + '\n')
			#print('RT: "' + rt + '"\n')

uecp = UECP_Frame_Decoder()

def parse_anc_bytes(anc_bytes) :
	global uecp
	for b in anc_bytes :
		need_more_data = uecp.add_byte(b)

		if not need_more_data :
			uecp.decode_frame()
			uecp = UECP_Frame_Decoder()


frame_len = int(int(sys.argv[1])/48*144)
print("Set frame length: " + str(frame_len))
packet = sys.stdin.buffer.read(frame_len)

while sys.stdin.buffer.read !="":
	packet = sys.stdin.buffer.read(frame_len)
		
	if len(packet) < frame_len :
		sys.exit(0)
	
	line_bytes = [int(i) for i in packet]
	
	line_bytes.reverse()

	anc_header = line_bytes[0]
	anc_bytes = None
	
	if anc_header == 0xFD :
		anc_len = line_bytes[1]
		if anc_len > 0:
			anc_bytes = line_bytes[2:2+anc_len]
	elif anc_header != 0x00 :
		anc_len = line_bytes[0]
		if anc_len > 0:
			anc_bytes = line_bytes[1:1+anc_len]
				
	if anc_bytes :
		parse_anc_bytes(anc_bytes)

import subprocess
import os


class new_fifo_window():
	def __init__(self, fifo_path):

		self.fifo_path = fifo_path
		try: 
			os.mkfifo(fifo_path)
		except:
			print('fifo already exists, but continue')

		self.proc = subprocess.Popen(['xterm', '-e', 'cat %s' % fifo_path])
		self.fd = open(fifo_path, 'w')
	def write(self, *outputs):
		for out in outputs:
			self.fd.write(str(out) + ' ')
		self.fd.write('\n')
		self.fd.flush()

	def __del__(self):
		self.proc.terminate()
		os.remove(self.fifo_path)
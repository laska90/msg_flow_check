from unittest import TestCase
import FileReaderStud
import PacketAssembler
from multiprocessing.pool import ThreadPool
import Queue
import time


class TestFileReaderStud(TestCase):
	def test_read_from_file_to_queue(self):
		result_queue = Queue.Queue()
		streamer = FileReaderStud.FileReaderStud('d:\dump.xml', result_queue)
		streamer.read_from_file()

	def test_read_to_packets(self):
		raw_queue = Queue.Queue()
		packet_queue = Queue.Queue()
		streamer = FileReaderStud.FileReaderStud('d:\dump.xml', raw_queue)
		packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
		stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
		packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
		counter = 0
		while True:
			try:
				temp = packet_queue.get(timeout=0.1)
				if temp:
					counter += 1
			except Queue.Empty:
				break
		self.assertEqual(counter, 9)

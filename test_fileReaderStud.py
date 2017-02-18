from unittest import TestCase
import FileReaderStud
import PacketAssembler
from multiprocessing.pool import ThreadPool
import Queue
import time
import PacketValidator
import RuleParser

class TestFileReaderStud(TestCase):
    def test_read_from_file_to_queue(self):
        result_queue = Queue.Queue()
        streamer = FileReaderStud.FileReaderStud('example.xml', result_queue)
        streamer.read_from_file()

    def test_read_to_packets(self):
        raw_queue = Queue.Queue()
        packet_queue = Queue.Queue()
        streamer = FileReaderStud.FileReaderStud('example.xml', raw_queue)
        packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
        stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
        packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
        counter = 0
        while True:
            try:
                temp = packet_queue.get(timeout=0.3)
                if temp is not None:
                    counter += 1
                    # print temp.xpath("/packet/proto[@name='frame']/field[@name='frame.number']/@show")
                    # print temp.xpath("//field[@name='frame.number']/@show")
                    # print temp.xpath("//*[@name='frame.number']/@show")
            except Queue.Empty:
                break
        self.assertEqual(counter, 22)

    def test_validate_packet(self):
        raw_queue = Queue.Queue()
        packet_queue = Queue.Queue()
        flow = PacketValidator.MessageHandler()
        flow['ip.src'] = ['193.108.181.130']
        streamer = FileReaderStud.FileReaderStud('example.xml', raw_queue)
        packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
        stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
        packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
        counter = 0
        while True:
            try:
                temp = packet_queue.get(timeout=0.3)
                result = flow.verify_rule(temp, """flow['ip.src'] == message["//*[@name='ip.src']/@show"]""")
                flow.update_flow(temp, """flow['ip.dst'] = message["//*[@name='ip.dst']/@show"]""")
                if result:
                    counter += 1
            except Queue.Empty:
                break
        self.assertEqual(counter, 10)


    def test_validate_packet_with_full_rule_set_passed(self):
        raw_queue = Queue.Queue()
        packet_queue = Queue.Queue()
        flow = PacketValidator.MessageHandler()
        flow['ip.failing'] = ['292.168.222.3']
        flow['ip.passing'] = ['192.168.222.3']
        streamer = FileReaderStud.FileReaderStud('example.xml', raw_queue)
        packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
        stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
        packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
        counter = 0
        the_message = packet_queue.get(timeout=1)
        passing_rules = ["""flow['ip.passing'] == message["//*[@name='ip.src']/@show"]"""]
        failing_rules = ["""flow['ip.failing'] == message["//*[@name='ip.src']/@show"]"""]
        update_rules = []
        verificator = PacketValidator.PacketValidator(passing_rules, failing_rules, update_rules)
        self.assertTrue(verificator.validate_packet(the_message, flow))

    def test_validate_packet_with_full_rule_set_failed(self):
        raw_queue = Queue.Queue()
        packet_queue = Queue.Queue()
        flow = PacketValidator.MessageHandler()
        flow['ip.failing'] = ['192.168.222.3']
        flow['ip.passing'] = ['292.168.222.3']
        streamer = FileReaderStud.FileReaderStud('example.xml', raw_queue)
        packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
        stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
        packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
        counter = 0
        the_message = packet_queue.get(timeout=1)
        passing_rules = ["""flow['ip.passing'] == message["//*[@name='ip.src']/@show"]"""]
        failing_rules = ["""flow['ip.failing'] == message["//*[@name='ip.src']/@show"]"""]
        update_rules = []
        verificator = PacketValidator.PacketValidator(passing_rules, failing_rules, update_rules)
        self.assertFalse(verificator.validate_packet(the_message, flow))


    def test_validate_packet_with_full_rule_set_ignored(self):
        raw_queue = Queue.Queue()
        packet_queue = Queue.Queue()
        flow = PacketValidator.MessageHandler()
        flow['ip.failing'] = ['292.168.222.3']
        flow['ip.passing'] = ['292.168.222.3']
        streamer = FileReaderStud.FileReaderStud('example.xml', raw_queue)
        packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
        stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
        packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
        counter = 0
        the_message = packet_queue.get(timeout=1)
        passing_rules = ["""flow['ip.passing'] == message["//*[@name='ip.src']/@show"]"""]
        failing_rules = ["""flow['ip.failing'] == message["//*[@name='ip.src']/@show"]"""]
        update_rules = []
        verificator = PacketValidator.PacketValidator(passing_rules, failing_rules, update_rules)
        self.assertIsNone(verificator.validate_packet(the_message, flow))

    def test_validate_packet_with_full_rule_set_passed_and_updated(self):
        raw_queue = Queue.Queue()
        packet_queue = Queue.Queue()
        flow = PacketValidator.MessageHandler()
        flow['ip.failing'] = ['292.168.222.3']
        flow['ip.passing'] = ['192.168.222.3']
        flow['tcp.failing'] = ['55393']
        streamer = FileReaderStud.FileReaderStud('example.xml', raw_queue)
        packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
        stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
        packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
        the_message = packet_queue.get(timeout=1)
        passing_rules = ["""flow['ip.passing'] == message["//*[@name='ip.src']/@show"]"""]
        failing_rules = ["""flow['ip.failing'] == message["//*[@name='ip.src']/@show"]""",
                         """flow['tcp.failing'] == message["//*[@name='tcp.srcport']/@show"]"""]
        update_rules = ["""flow['ip.updated'] = message["//*[@name='ip.dst']/@show"]"""]
        verificator = PacketValidator.PacketValidator(passing_rules, failing_rules, update_rules)
        self.assertTrue(verificator.validate_packet(the_message, flow))
        self.assertEqual(flow['ip.updated'], ['193.108.181.130'])

    def test_validate_packet_with_full_rule_set_passed_and_updated_from_file(self):
        raw_queue = Queue.Queue()
        packet_queue = Queue.Queue()
        flow = PacketValidator.MessageHandler()
        flow['ip.failing'] = ['292.168.222.3']
        flow['ip.passing'] = ['192.168.222.3']
        flow['tcp.failing'] = ['55393']
        streamer = FileReaderStud.FileReaderStud('example.xml', raw_queue)
        packet_assembler = PacketAssembler.PacketAssembler(raw_queue, packet_queue, '(<packet>(?:.|\n)*?<\/packet>)')
        stream_thread = ThreadPool(processes=1).apply_async(streamer.read_from_file)
        packet_thread = ThreadPool(processes=1).apply_async(packet_assembler.assemble_packets)
        the_message = packet_queue.get(timeout=1)
        verificator = RuleParser.RuleParser('rules.xml').parse_rules_from_file()[0]
        self.assertTrue(verificator.validate_packet(the_message, flow))
        self.assertEqual(flow['ip.updated'], ['193.108.181.130'])


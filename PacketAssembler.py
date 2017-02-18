import re
import Queue
from lxml import etree
import Message


class PacketAssembler(object):
    def __init__(self, input_queue, output_queue, regex):
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.regex = re.compile(regex)

    def assemble_packets(self):
        input_buffer = ""
        while True:
            try:
                input_buffer += self.input_queue.get(timeout=0.5)
                packets = re.findall(self.regex, input_buffer)
                if packets:
                    for item in packets:
                        parsed_packet = Message.Message(item)
                        self.output_queue.put(parsed_packet)
                        input_buffer = re.sub(self.regex, '', input_buffer, count=1)
                self.input_queue.task_done()
            except Queue.Empty:
                pass

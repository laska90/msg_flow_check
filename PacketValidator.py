import RuleParser
import Queue
from multiprocessing.pool import ThreadPool
import PacketAssembler
import FileReaderStud
from multiprocessing import TimeoutError

class MessageHandler(dict):
    def __init__(self, setup_list=[]):
        super(dict, self).__init__()
        for updater in setup_list:
            self.update_flow(None, updater)

    def verify_rule(flow, message, rule):
        return eval(rule)

    def update_flow(flow, message, rule):
        exec(rule)


class PacketValidator(object):
    def __init__(self, passing_rules, failing_rules, update_rules):
        self.passing_rules = passing_rules
        self.failing_rules = failing_rules
        self.update_rules = update_rules

    def validate_packet(self, msg, flow):
        for failing_rule in self.failing_rules:
            temp_result = flow.verify_rule(msg, failing_rule)
            if temp_result:
                return False
        for passing_rule in self.passing_rules:
            temp_result = flow.verify_rule(msg, passing_rule)
            if not temp_result:
                return None
        for update_rule in self.update_rules:
            flow.update_flow(msg, update_rule)
        return True


class MessageFlowValidator(object):
    def __init__(self, flow_file, packet_queue):
        self.status = None
        self.packet_queue = packet_queue
        self.flow = MessageHandler(RuleParser.RuleParser(flow_file).initial_setup_from_file())
        self.validator_list = RuleParser.RuleParser(flow_file).parse_rules_from_file()

    def start_validation(self):
        packet_buffer = list()
        for validator_rule in self.validator_list:
            rule_status = None
            while rule_status is None:
                msg = (self.packet_queue.get())
                rule_status = validator_rule.validate_packet(msg, self.flow)
                if rule_status == False:
                    self.status = False
                    return False
        return True


class StreamValidator(object):
    def __init__(self, packet_source, rule_file):
        self.raw_queue = Queue.Queue()
        self.packet_queue = Queue.Queue()
        self.streamer = FileReaderStud.FileReaderStud(packet_source, self.raw_queue)
        self.packet_assembler = PacketAssembler.PacketAssembler(self.raw_queue, self.packet_queue)
        self.msg_flow_validator = MessageFlowValidator(rule_file, self.packet_queue)
        self.streamer_thread = ThreadPool(processes=1)
        self.assembler_thread = ThreadPool(processes=1)
        self.validator_thread = ThreadPool(processes=1)
        self.validator_thread_result = None

    def __del__(self):
        self.streamer_thread.terminate()
        self.assembler_thread.terminate()
        self.validator_thread.terminate()

    def start_capture(self):
        self.streamer_thread.apply_async(self.streamer.read_from_file)
        self.assembler_thread.apply_async(self.packet_assembler.assemble_packets)
        self.validator_thread_result = self.validator_thread.apply_async(self.msg_flow_validator.start_validation)

    def stop_capture(self, timeout=2):
        try:
            return self.validator_thread_result.get(timeout)
        except TimeoutError:
            return None

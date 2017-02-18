from lxml import etree
import PacketValidator

class RuleParser(object):
    def __init__(self, file):
        self.filepath = file

    def parse_rules_from_file(self):
        rules = etree.parse(self.filepath)
        msg_flow = []
        for rule in rules.xpath('./rule'):
            pas = []
            fail = []
            upd = []
            for subrule in rule.xpath('./passing_rule/text()'):
                pas.append(subrule)
            for subrule in rule.xpath('./failing_rule/text()'):
                fail.append(subrule)
            for subrule in rule.xpath('./update_rule/text()'):
                upd.append(subrule)
            msg_flow.append(PacketValidator.PacketValidator(pas, fail, upd))
        return msg_flow
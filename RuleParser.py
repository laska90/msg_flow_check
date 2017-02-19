from lxml import etree
import PacketValidator


class RuleParser(object):
    def __init__(self, file):
        self.filepath = file

    def parse_rules_from_file(self):
        rules = etree.parse(self.filepath)
        return [PacketValidator.PacketValidator(rule.xpath('./passing_rule/text()'),
                                                rule.xpath('./failing_rule/text()'),
                                                rule.xpath('./update_rule/text()')) for rule in
                rules.xpath('./rule')]

    def initial_setup_from_file(self):
        rules = etree.parse(self.filepath)
        return rules.xpath('./setup/setup_value/text()')
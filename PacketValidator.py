
class MessageHandler(dict):
    def __init__(self, *args, **kwargs):
        super(dict, self).__init__(*args, **kwargs)

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
from lxml import etree


class Message(object):
    def __init__(self, msg):
        self.msg = etree.fromstring(msg)

    def __getitem__(self, item):
        return self.msg.xpath(item)


import time


class FileReaderStud(object):
    def __init__(self, filename, queue):
        self.filename = filename
        self.queue = queue

    def read_from_file(self):
        with open(self.filename, 'r') as file:
            while True:
                output = file.read(102400)
                self.queue.put(output)
                if not output:
                    break
            file.close()

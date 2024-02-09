import logging
import queue

from Miniserver import Miniserver


logging.basicConfig(level=logging.INFO)


class Controller:

    def __init__(self):
        commands = queue.Queue()

        # read values from the AI1 and AI2 input fields, declared in the program as analog_in_1 and analog_in_2:
        commands.put("jdev/sps/io/analog_in_1")

        commands.put("jdev/sps/io/analog_in_2")

        self.ms = Miniserver(commands)

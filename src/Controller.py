import logging
import queue
from time import sleep

from Miniserver import Miniserver


logging.basicConfig(level=logging.INFO)


class Controller:

    def __init__(self):
        commmands = queue.Queue()

        # read values from the AI1 and AI2 input fields, declared in the program as analog_in_1 and analog_in_2:
        commmands.put("jdev/sps/io/analog_in_1")

        commmands.put("jdev/sps/io/analog_in_2")

        self.ms = Miniserver(commmands)

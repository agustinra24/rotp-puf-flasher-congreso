"""
This class is designed for the semaphore led to noise levels in environment

Status: |
      3 | Red -> High level of Noise
      2 | Yellow -> Mediums level of Noise
      1 | Green -> Lows level of Noise
      0 | unknown
"""
from machine import Pin  # Import necessary modules for GPIO and ADC

class SemaphoreLed:
    def __init__(self, out_pin_red, out_pin_yellow, out_pin_green):
        """
        Initialize the Semaphore Led.

        Parameters:
        output pin (int): The GPIO pin where the microphone output is connected.
        """
        self.led_red = Pin(out_pin_red, Pin.OUT, value=0)
        self.led_yellow = Pin(out_pin_yellow, Pin.OUT, value=0)
        self.led_green = Pin(out_pin_green, Pin.OUT, value=0)
        self.status = 0

    def set_green(self):
        print("Setting the semaphore to Green!")
        self.led_red.value(0)
        self.led_yellow.value(0)
        self.led_green.value(1)
        self.status = 1

    def set_yellow(self):
        print("Setting the semaphore to Yellow!")
        self.led_red.value(0)
        self.led_yellow.value(1)
        self.led_green.value(0)
        self.status = 2

    def set_red(self):
        print("Setting the semaphore to Red!")
        self.led_red.value(1)
        self.led_yellow.value(0)
        self.led_green.value(0)
        self.status = 3

    def read_semaphore_status(self):
        return self.status

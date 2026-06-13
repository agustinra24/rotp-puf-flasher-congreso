from machine import Pin, PWM
import time

class InfraredModule:
    def __init__(self, input_pin, modulation_frequency=38000, duty_pwm=0):
        """
        Initialize the IR sender module

        Parameters:
        input_pin (int): The GPIO pin where the microphone output is connected.
        """
        self.ir_sender = PWM(Pin(input_pin), freq=modulation_frequency, duty=duty_pwm)

    def send_raw_data(self, raw_data:list):
        """Send the IR signal using rawData timing."""
        for i in range(0, len(raw_data), 2):
            self.ir_sender.duty(512)  # IR LED ON (50% duty cycle)
            time.sleep_us(raw_data[i])  # ON duration
            self.ir_sender.duty(0)  # IR LED OFF
            time.sleep_us(raw_data[i + 1])  # OFF duration
        self.ir_sender.duty(0)  # Ensure IR LED is OFF


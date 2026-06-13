"""
This class is designed for the MAX4466 Microphone Sensor.
It reads analog values from the microphone, converts them to voltage,
and can sample multiple readings to compute an average value.
"""

from machine import Pin, ADC  # Import necessary modules for GPIO and ADC
import utime  # Import time module for delays

class MicrophoneSensor:
    def __init__(self, input_pin):
        """
        Initialize the microphone sensor.

        Parameters:
        input_pin (int): The GPIO pin where the microphone output is connected.
        """
        self.sensor = ADC(Pin(input_pin))  # Set up the ADC input pin
        self.sensor.atten(ADC.ATTN_11DB)  # Configure ADC attenuation to read up to 3.3V
        self.sensor.width(ADC.WIDTH_12BIT)  # Set ADC resolution to 12-bit (0-4095)

    def read_sensor(self):
        """
        Read the raw ADC value and convert it to voltage.

        Returns:
        float: The voltage level corresponding to the analog reading.
        """
        value = self.sensor.read()  # Read the ADC value (range: 0 to 4095)
        voltage = (value / 4095) * 3.3  # Convert ADC value to voltage (0-3.3V)
        return voltage  # Return the calculated voltage

    def sample_average(self, number_of_samples, microseconds):
        """
        Take multiple samples from the microphone and compute the average voltage.

        Parameters:
        number_of_samples (int): The number of readings to take.
        microseconds (int): Delay (in milliseconds) between each sample.

        Returns:
        float: The average voltage of the sampled readings.
        """
        lecture = 0  # Initialize variable to store sum of readings
        for i in range(number_of_samples):
            lecture += self.read_sensor()  # Add each reading to total sum
            utime.sleep_ms(microseconds)  # Wait for specified time between samples
        return lecture / number_of_samples  # Return the average value


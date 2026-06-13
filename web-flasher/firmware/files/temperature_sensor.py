"""
This code is used to read data from a DHT11 humidity and temperature sensor.
The sensor provides temperature in degrees Celsius and relative humidity in percentage.
"""

import dht  # Import the DHT sensor module for handling temperature and humidity
from machine import Pin  # Import Pin class to define GPIO pins
import time

class TemperatureSensor:
    """
    A class to interface with the DHT11 sensor and retrieve temperature and humidity values.
    """

    def __init__(self, input_pin):
        """
        Initialize the DHT11 sensor.

        Parameters:
        temperature_pin (int): The GPIO pin number where the DHT11 data pin is connected.
        """
        self.sensor = dht.DHT11(Pin(input_pin))  # Initialize the DHT11 sensor on the specified pin

    def read_temperature(self):
        """
        Read and return the temperature from the DHT11 sensor.

        Returns:
        int: Temperature value in degrees Celsius.
        """
        self.sensor.measure()  # Trigger a measurement to update temperature and humidity readings
        temperature = self.sensor.temperature()  # Get the temperature value
        time.sleep(0.9) # this delay is necessary due to OSError: [Errno 116] ETIMEDOUT
        return temperature  # Return the temperature in Celsius

    def read_humidity(self):
        """
        Read and return the humidity from the DHT11 sensor.

        Returns:
        int: Humidity value in percentage (%RH).
        """
        self.sensor.measure()  # Trigger a new measurement
        humidity = self.sensor.humidity()  # Get the humidity value
        time.sleep(0.9) # this delay is necessary due to OSError: [Errno 116] ETIMEDOUT
        return humidity  # Return the humidity as a percentage

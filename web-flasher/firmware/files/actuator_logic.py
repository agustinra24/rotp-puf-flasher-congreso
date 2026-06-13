"""
Local actuator logic for the IoT device.

Evaluates sensor readings against configurable thresholds and controls
actuators (LED semaphore, IR transmitter) without depending on server
commands. The API does not return actuator instructions, so all
decisions are made locally on the device.

Replaces Processing_data.py which depended on server response fields
(2_noise_level, 3_temperature, 4_humidity) that the current API
no longer provides.
"""

import time


class ActuatorLogic:
    """Evaluate sensor data against thresholds and control actuators."""

    def __init__(self, thresholds: dict, semaphore, ir_sender):
        """
        Parameters:
            thresholds: Dict with keys: temp_high, temp_low, humidity_high,
                        noise_high_v, noise_medium_v.
            semaphore:  SemaphoreLed instance.
            ir_sender:  InfraredModule instance.
        """
        self.temp_high = thresholds["temp_high"]
        self.temp_low = thresholds["temp_low"]
        self.humidity_high = thresholds["humidity_high"]
        self.noise_high = thresholds["noise_high_v"]
        self.noise_medium = thresholds["noise_medium_v"]
        self.semaphore = semaphore
        self.ir = ir_sender

    def evaluate(self, temperature: float, humidity: float, noise_voltage: float):
        """
        Evaluate all sensor readings and trigger actuator actions.

        Parameters:
            temperature:   Temperature in Celsius (from DHT11).
            humidity:      Relative humidity percentage (from DHT11).
            noise_voltage: Microphone voltage level (from MAX4466 ADC).
        """
        self._evaluate_noise(noise_voltage)
        self._evaluate_climate(temperature, humidity)

    def _evaluate_noise(self, voltage: float):
        """Set LED semaphore color based on noise level thresholds."""
        if voltage >= self.noise_high:
            self.semaphore.set_red()
        elif voltage >= self.noise_medium:
            self.semaphore.set_yellow()
        else:
            self.semaphore.set_green()

    def _evaluate_climate(self, temperature: float, humidity: float):
        """Send IR signal when temperature is low and humidity is high."""
        if temperature <= self.temp_low and humidity >= self.humidity_high:
            print("[actuator] Low temp + high humidity: sending IR signal")
            for _ in range(3):
                self.ir.send_raw_data(self._get_ir_data())
                time.sleep(0.5)

    @staticmethod
    def _get_ir_data() -> list:
        """Get IR timing data from config_manager constants."""
        from config_manager import IR_RAW_DATA
        return IR_RAW_DATA

"""
Toggle de envio por boton fisico (GPIO 0 / BOOT).

Presionar el boton alterna entre enviar y pausar la telemetria
al servidor. Los sensores y actuadores siguen funcionando siempre.
"""

from machine import Pin
import time


class SendToggle:
    """Toggle de envio controlado por boton con debounce por IRQ."""

    def __init__(self, pin=0, debounce_ms=200):
        self._sending = True
        self._last_press = 0
        self._debounce_ms = debounce_ms
        self._prev_state = True
        self._pin = Pin(pin, Pin.IN, Pin.PULL_UP)
        self._pin.irq(trigger=Pin.IRQ_FALLING, handler=self._irq_handler)

    def _irq_handler(self, pin):
        now = time.ticks_ms()
        if time.ticks_diff(now, self._last_press) < self._debounce_ms:
            return
        self._last_press = now
        self._sending = not self._sending
        # No print() aqui: allocar memoria en ISR no es seguro en MicroPython.
        # El cambio de estado se detecta y logea en check_and_log().

    @property
    def sending_enabled(self):
        return self._sending

    def check_and_log(self):
        """Llamar desde el main loop para logear cambios de estado de forma segura."""
        if self._sending != self._prev_state:
            state = "ENABLED" if self._sending else "DISABLED"
            print("[button] Sending {}".format(state))
            self._prev_state = self._sending

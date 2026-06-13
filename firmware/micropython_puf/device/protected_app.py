"""Tiny plaintext source module for the encrypted .mpy firmware PoC.

This source exists only as the host-side build input. The generated
`protected_app.mpy.enc` envelope is the artifact that should be uploaded to the
ESP32 for the runtime demo.
"""


DEMO_SECRET_MARKER = "PUF_BOUND_FIRMWARE_DEMO_SECRET_V1"


def main():
    """Run a visible payload after the loader has verified and decrypted it."""
    print("PROTECTED_APP_MPY_OK")
    print("protected_marker_len={}".format(len(DEMO_SECRET_MARKER)))
    return {
        "status": "ok",
        "marker": DEMO_SECRET_MARKER,
    }

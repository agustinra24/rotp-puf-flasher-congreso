"""Clear-text entrypoint for the PUF-bound encrypted firmware PoC."""

import secure_firmware_loader


RESULT = secure_firmware_loader.run_encrypted_mpy_module()
print("PUF_MPY_FIRMWARE_LOADER_OK mpy_sha256={}".format(RESULT["mpy_sha256"]))

import logging

from .wrapper import ImmuneGate

__version__ = "0.9.0"

# Best Practice für Python-Libraries: NullHandler verhindert
# "No handlers could be found for logger" Warnungen beim Import.
# Anwender konfigurieren ihr eigenes Logging-Setup.
logging.getLogger("immunegate").addHandler(logging.NullHandler())

__all__ = ["ImmuneGate", "__version__"]

import os
import sys

# Ensure backend directory is first in sys.path so 'app' always refers to backend/app
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

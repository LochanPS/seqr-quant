"""Put the agent package on the path so `import seqr_agent` works from the tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

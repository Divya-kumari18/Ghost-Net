"""Keep historical launch paths on the same authenticated implementation."""
import importlib.util
from pathlib import Path
import sys

def load_app():
    name='ghostnet_unified_http'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name('app.py'))
        module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module
        try:spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(name,None)
            raise
    return sys.modules[name].app

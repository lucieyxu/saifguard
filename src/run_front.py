import os
import sys
from mesop.server.wsgi_app import create_app
from mesop.bin.bin import make_path_absolute, execute_main_module

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    absolute_path = make_path_absolute("front.py")
    sys.path = [os.path.dirname(absolute_path), *sys.path]
    
    app = create_app(
        prod_mode=True,
        run_block=lambda: execute_main_module(absolute_path=absolute_path),
    )
    app._flask_app.run(host="0.0.0.0", port=port)

import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn

from anysoar_console.app import ConsoleConfig, create_app

from .console_harness import Console


@pytest.fixture
def console(tmp_path: Path) -> Iterator[Console]:
    config = ConsoleConfig(
        operator="analyst1",
        audit_log=tmp_path / "audit.jsonl",
        kill_switch=tmp_path / "STOP",
    )
    server = uvicorn.Server(
        uvicorn.Config(create_app(config), host="127.0.0.1", port=0, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield Console(f"http://127.0.0.1:{port}", config)
    server.should_exit = True
    thread.join(timeout=5)

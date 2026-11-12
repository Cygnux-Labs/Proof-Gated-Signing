import os, signal, socket, subprocess, sys, time
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture(scope="session")
def world():
    """The paper's test world on a fresh Hardhat node (started here, stopped at the end)."""
    if not os.path.exists(os.path.join(ROOT, "node_modules", ".bin", "hardhat")):
        pytest.skip("needs the local chain: run npm ci")
    from pgs.world import World, w3_connect
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    node = subprocess.Popen(["npx", "hardhat", "node", "--port", str(port)], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        for _ in range(120):
            try:
                w3 = w3_connect(f"http://127.0.0.1:{port}")
                break
            except Exception:
                time.sleep(0.5)
        else:
            pytest.fail("hardhat node did not start")
        yield World(w3).build()
    finally:
        os.killpg(node.pid, signal.SIGTERM)
        node.wait()


@pytest.fixture
def w(world):
    sid = world.snapshot()
    yield world
    world.revert(sid)

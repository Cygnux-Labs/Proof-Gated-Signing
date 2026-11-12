"""Use PGS as a library on a local Hardhat node: one allowed swap, one refused payment, and drift.

The test world only deploys a wallet, tokens and a pool to play with; what pgs.check sees is
plain data: a Policy, the calls, and a state provider for the chain.

usage: ./node.sh 8545 && python examples/check_tx.py --port 8545
"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pgs
from pgs.world import World, w3_connect, E18

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=8545)
w = World(w3_connect(f"http://127.0.0.1:{ap.parse_args().port}")).build()
A = w.addr
name = {A["USDC"]: "USDC", A["WETH"]: "WETH", "0x" + "00" * 20: "ETH"}

policy = pgs.Policy(
    prices={"USDC": 1.0, "WETH": 2500.0, "ETH": 2500.0},      # nominal USD prices
    assets={"USDC": A["USDC"], "WETH": A["WETH"]},           # token addresses ("ETH" is the native coin)
    band=0.005,                                              # true prices are within +-0.5%
    max_rel_loss=0.03, floor_usd=25.0, window_usd=5000.0,    # lose at most 3% + $25 per tx, $5k per session
    payees={w.alice: 20_000.0},                              # who may be paid, and up to how much per tx
    trusted_spenders={A["POOL_UW"]})                         # who may keep an allowance
chain = pgs.Web3Chain(w.w3, wallet=A["WALLET"], sender=w.agent)
session = pgs.Session()

swap = [w.call("USDC", "approve", A["POOL_UW"], 10_000 * E18),
        w.call("POOL_UW", "swap", A["USDC"], 10_000 * E18, 0, A["WALLET"])]   # minOut 0: no slippage bound
v = pgs.check(policy, swap, chain, session)
print("swap 10,000 USDC -> WETH:", "allowed" if v.allow else v.reasons)
for token, min_delta in v.post[0]:
    print(f"  bound: wallet {name[token]} changes by at least {min_delta / E18:,.4f}")
print(f"  proof: {len(v.proof.splitlines())} lines of SMT-LIB that Z3 found unsat")

v2 = pgs.check(policy, [w.call("USDC", "transfer", w.attacker, 1_000 * E18)], chain, session)
print("transfer 1,000 USDC to an unknown address: refused" if not v2.allow else "allowed?!")
print("  reasons:", v2.reasons[0], "| counterexample:", v2.counterexample)

# Someone trades in the pool after the check and before the swap executes.
w.tx(w.c["USDC"].functions.approve(A["POOL_UW"], 500_000 * E18), w.searcher)
w.tx(w.c["POOL_UW"].functions.swap(A["USDC"], 500_000 * E18, 0, w.searcher), w.searcher)
try:
    w.exec_checked(swap, *v.post)
    print("after drift: executed")
except Exception as e:
    print("after drift: the wallet reverted the swap on-chain:", "guard:balance" in str(e))

"""pgs.check through its public API. Tests that take `w` run on the paper's test world on a
local Hardhat node (started by conftest.py); the others need no chain."""
import itertools, json, os, random, subprocess, sys
from fractions import Fraction

import pytest
import z3
from web3 import Web3

import pgs
from pgs.guard import ZERO
from pgs.defenses import make_policy

E18 = 10**18
A, B, C = (Web3.to_checksum_address("0x" + c * 40) for c in "abc")


def chain(w):
    return pgs.Web3Chain(w.w3, w.addr["WALLET"], w.agent)


def swap(w, usdc, min_out=0):
    return [w.call("USDC", "approve", w.addr["POOL_UW"], usdc),
            w.call("POOL_UW", "swap", w.addr["USDC"], usdc, min_out, w.addr["WALLET"])]


def front_run(w, usdc):
    w.tx(w.c["USDC"].functions.approve(w.addr["POOL_UW"], usdc), w.searcher)
    w.tx(w.c["POOL_UW"].functions.swap(w.addr["USDC"], usdc, 0, w.searcher), w.searcher)


def test_allows_a_swap_and_a_payment_with_bounds(w):
    calls = swap(w, 1_000 * E18) + [w.call("USDC", "transfer", w.alice, 500 * E18)]
    v = pgs.check(make_policy(w), calls, chain(w), pgs.Session())
    assert v.allow and v.reasons == [] and v.counterexample is None
    bal, allow, own, recv = v.post
    assert dict(bal)[w.addr["USDC"]] == -1_500 * E18           # outflow may not exceed the simulated one
    assert 0 < dict(bal)[w.addr["WETH"]] < v.effects.delta["WETH"]   # inflow at least (1 - tau) of it
    assert recv == [(w.addr["USDC"], w.alice, 500 * E18)]          # Alice must receive what is credited
    assert own == [(w.addr["VAULT"], w.addr["WALLET"])]
    alice0 = w.balance("USDC", w.alice)
    assert w.exec_checked(calls, *v.post).status == 1
    assert w.balance("USDC", w.alice) - alice0 == 500 * E18


def test_refuses_a_transfer_to_an_unknown_address_with_a_counterexample(w):
    v = pgs.check(make_policy(w), [w.call("USDC", "transfer", w.attacker, 1_000 * E18)], chain(w), pgs.Session())
    assert not v.allow and v.post is None and v.proof is None
    assert f"eoa-recipient-not-allowlisted:{w.attacker}" in v.reasons
    assert v.counterexample["violated"] == "relative-loss"
    assert 995 <= v.counterexample["loss_usd"] <= 1005               # 1,000 USDC at a price in the 0.5% band


def test_session_budget_refuses_once_spent(w):
    calls = swap(w, 1_000 * E18)
    assert pgs.check(make_policy(w), calls, chain(w), pgs.Session(spent_usd=4_900.0)).allow
    v = pgs.check(make_policy(w), calls, chain(w), pgs.Session(spent_usd=4_999.0))
    assert not v.allow and v.counterexample["violated"] == "window"


def test_proof_rechecks_and_bounds_imply_the_policy(w):
    """Theorem 1, sampled: every outcome at or above the bounds, at every price in the band, meets the policy."""
    P = make_policy(w)
    v = pgs.check(P, swap(w, 20_000 * E18) + [w.call("USDC", "transfer", w.alice, 500 * E18)], chain(w), pgs.Session())
    assert v.allow
    s = z3.Solver()
    s.from_string(v.proof)
    assert s.check() == z3.unsat                                       # any SMT solver can recheck it
    key = {a: k for k, a in P.assets.items()} | {ZERO: "ETH"}
    lo = {key[a]: m for a, m in v.post[0]}
    pay = {k: Fraction(v.effects.payments.get(k, 0), E18) for k in lo}
    q = lambda x: Fraction(x).limit_denominator(10**6)
    band = {k: (q(P.prices[k]) * q(1 - P.band), q(P.prices[k]) * q(1 + P.band)) for k in lo}
    rnd = random.Random(1)
    corners = [(dict(zip(band, c)), lo) for c in itertools.product(*band.values())]   # on the bounds
    inside = [({k: a + (b - a) * Fraction(rnd.randint(0, 1000), 1000) for k, (a, b) in band.items()},
               {k: m + rnd.randint(0, abs(m) // 10 + E18) for k, m in lo.items()}) for _ in range(500)]
    for p, d in corners + inside:
        loss = -sum((Fraction(d[k], E18) + pay[k]) * p[k] for k in lo)
        vout = sum((Fraction(max(-lo[k], 0), E18) - pay[k]) * p[k] for k in lo)
        assert loss <= q(P.max_rel_loss) * vout + q(P.floor_usd) and loss <= q(P.window_usd)


def test_state_drift_reverts_under_bounds_and_costs_the_wallet_without(w):
    P, ch = make_policy(w), chain(w)
    calls = swap(w, 100_000 * E18)                     # no minOut: the agent set no slippage bound
    v = pgs.check(P, calls, ch, pgs.Session())
    assert v.allow
    sid = w.snapshot()
    front_run(w, 500_000 * E18)                        # the state drifts after the check
    with pytest.raises(Exception, match="guard:balance"):
        w.exec_checked(calls, *v.post)
    w.revert(sid)
    v = pgs.check(P, calls, ch, pgs.Session(), "sim")  # simulation and proof alone: no bounds to enforce
    assert v.allow and v.post is None
    weth0 = w.balance("WETH", w.addr["WALLET"])
    front_run(w, 500_000 * E18)
    assert w.exec_raw(calls).status == 1
    assert w.balance("WETH", w.addr["WALLET"]) - weth0 < 0.95 * v.effects.delta["WETH"]


def test_prove_needs_no_chain():
    P = pgs.Policy(prices={"USDC": 1.0, "WETH": 2500.0}, assets={"USDC": A, "WETH": B}, band=0.005)
    fair = {"USDC": -1_000 * E18, "WETH": 4 * E18 // 10}
    assert pgs.prove(P, fair, True, {})[0]
    ok, cex, smt2 = pgs.prove(P, {"USDC": -1_000 * E18, "WETH": 3 * E18 // 10}, True, {})
    assert not ok and smt2 is None and cex["violated"] == "relative-loss"
    assert pgs.prove(P, fair, True, {}, spent_usd=4_999.0)[1]["violated"] == "window"


POLICY = pgs.Policy(prices={"USDC": 1.0, "ETH": 2500.0}, assets={"USDC": A}, payees={B: 100.0})
OK = {"target": C, "value": 0, "data": "0x"}


@pytest.mark.parametrize("calls", [
    OK,                                                   # not a list
    [{**OK, "target": "0x1234"}],                         # not an address
    [{**OK, "value": -1}],
    [{**OK, "value": 1.5}],
    [{**OK, "value": True}],
    [{**OK, "data": "a9059cbb"}],                         # no 0x
    [{**OK, "data": "0xzz"}],
    [{**OK, "data": "0xabc"}],                            # odd length
    [{"target": C, "value": 0}],                          # missing data
    [{**OK, "operation": 1}],                             # unknown field, e.g. a Safe delegatecall flag
])
def test_malformed_calls_are_refused_before_touching_the_chain(calls):
    with pytest.raises(ValueError):
        pgs.check(POLICY, calls, None, pgs.Session())


@pytest.mark.parametrize("policy, mode", [
    (pgs.Policy(prices={"USDC": 1.0}), "sim+assert"),                                   # no token address
    (pgs.Policy(prices={"USDC": 1.0}, assets={"USDC": A, "DAI": B}), "sim+assert"),     # unpriced asset
    (pgs.Policy(prices={"USDC": 1.0}, assets={"USDC": A.lower()}), "sim+assert"),       # not checksummed
    (pgs.Policy(prices={"USDC": 1.0}, assets={"USDC": A}, payees={B.lower(): 1.0}), "sim+assert"),
    (pgs.Policy(prices={"USDC": 1.0}, assets={"USDC": A}, band=1.5), "sim+assert"),
    (pgs.Policy(prices={"USDC": 1.0}, assets={"USDC": A}, payees={B: "100"}), "sim+assert"),   # cap not a number
    (pgs.Policy(prices={"USDC": None}, assets={"USDC": A}), "sim+assert"),                     # price not a number
    (POLICY, "assert"),
])
def test_malformed_policy_or_mode_is_refused(policy, mode):
    with pytest.raises(ValueError):
        pgs.check(policy, [OK], None, pgs.Session(), mode)


def test_a_session_is_required():
    with pytest.raises(ValueError, match="session"):
        pgs.check(POLICY, [OK], None, None)


def test_selector_only_transfer_to_a_tracked_token_is_refused_clearly():
    with pytest.raises(ValueError, match="needs 68"):
        pgs.check(POLICY, [{"target": A, "value": 0, "data": "0xa9059cbb"}], None, pgs.Session())


def test_lowercase_target_is_checksummed_before_simulating(w):
    P, ch, calls = make_policy(w), chain(w), swap(w, 1_000 * E18)
    v = pgs.check(P, [{**c, "target": c["target"].lower()} for c in calls], ch, pgs.Session())
    assert v.allow and v.post == pgs.check(P, calls, ch, pgs.Session()).post


def test_session_rechecks_an_allowance_granted_earlier(w):
    w.exec_raw([w.call("USDC", "approve", w.addr["DRAINER"], 1_000 * E18)])   # granted outside this batch
    P, ch, calls = make_policy(w), chain(w), swap(w, 1_000 * E18)
    assert pgs.check(P, calls, ch, pgs.Session()).allow                      # a new session doesn't know it
    v = pgs.check(P, calls, ch, pgs.Session(allowance_pairs={(w.addr["USDC"], w.addr["DRAINER"])}))
    assert not v.allow and v.reasons == [f"residual-allowance:{w.addr['DRAINER']}"]


def test_check_leaves_the_chain_unchanged_under_python_O(w):
    """The simulation must be reverted even when asserts are stripped."""
    pay = w.call("USDC", "transfer", w.alice, 10 * E18)
    script = (
        "import json, sys; from web3 import Web3; import pgs\n"
        "url, wallet, agent, usdc, alice, data = sys.argv[1:]\n"
        "P = pgs.Policy(prices={'USDC': 1.0}, assets={'USDC': usdc}, payees={alice: 100.0})\n"
        "ch = pgs.Web3Chain(Web3(Web3.HTTPProvider(url)), wallet, agent)\n"
        "v = pgs.check(P, [{'target': usdc, 'value': 0, 'data': data}], ch, pgs.Session())\n"
        "print(json.dumps({'debug': __debug__, 'allow': v.allow}))\n")
    before = (w.balance("USDC", w.alice), w.balance("USDC", w.addr["WALLET"]), w.w3.eth.block_number)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run([sys.executable, "-O", "-c", script, w.w3.provider.endpoint_uri, w.addr["WALLET"], w.agent,
                          w.addr["USDC"], w.alice, pay["data"]], cwd=root, capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == {"debug": False, "allow": True}
    assert (w.balance("USDC", w.alice), w.balance("USDC", w.addr["WALLET"]), w.w3.eth.block_number) == before

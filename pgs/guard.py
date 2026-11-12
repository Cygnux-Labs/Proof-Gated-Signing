"""Proof-Gated Signing (PGS): simulate -> extract effects -> prove policy (Z3) ->
(optionally) compile on-chain post-conditions whose satisfaction is *proved* to imply
the policy, so the guarantee survives state drift between simulation and inclusion.

Public API: check(policy, calls, chain, session=None, mode="sim+assert") -> Verdict.
`chain` is a state provider (see pgs.chain.Web3Chain for the methods it needs).
"""
import time
from dataclasses import dataclass, field
from fractions import Fraction
import z3
from web3 import Web3

E18 = 10**18
ZERO = "0x" + "00" * 20
TRANSFER_T = "0x" + Web3.keccak(text="Transfer(address,address,uint256)").hex().replace("0x", "")
APPROVAL_T = "0x" + Web3.keccak(text="Approval(address,address,uint256)").hex().replace("0x", "")
SEL_TRANSFER = Web3.keccak(text="transfer(address,uint256)")[:4].hex().replace("0x", "")
MODES = ("sim", "sim+assert")


def _h(x):
    x = x.hex() if not isinstance(x, str) else x
    return x if x.startswith("0x") else "0x" + x


def _topic_addr(t):
    return Web3.to_checksum_address("0x" + _h(t)[-40:])


@dataclass
class Policy:
    prices: dict            # asset key -> nominal USD price (float); "ETH" is the native coin
    assets: dict = field(default_factory=dict)        # asset key -> token address, for every priced key but "ETH"
    band: float = 0.01      # oracle uncertainty: true price in [p(1-band), p(1+band)]
    max_rel_loss: float = 0.03   # unexplained value loss <= s * value_out + floor
    floor_usd: float = 25.0
    window_usd: float = 5000.0   # cumulative unexplained loss budget per session
    payees: dict = field(default_factory=dict)       # address -> per-tx cap in USD
    trusted_spenders: set = field(default_factory=set)  # may retain residual allowance
    owned: list = field(default_factory=list)         # contracts (with owner()) whose owner must stay the wallet
    inflow_tol: float = 0.01     # slack on received amounts when compiling post-conditions


@dataclass
class Effects:
    reverted: bool
    delta: dict              # asset key -> int (wei-units)
    residual_allow: dict     # (token_addr, spender) -> int after tx
    owners_after: dict       # contract addr -> owner after
    eoa_outflows: list       # (recipient, asset_key, amount) for value leaving to EOAs
    payments: dict           # asset_key -> amount paid to allowlisted payees at top level (fixed)
    payment_usd_by_payee: dict
    unknown_tokens: set
    gas_used: int = 0
    receipts: dict = field(default_factory=dict)   # (payee, asset_key) -> credited amount (enforced on-chain)


@dataclass
class Session:
    """What one guard remembers between transactions: realized unexplained loss (against
    Policy.window_usd) and every (token, spender) the wallet has approved."""
    spent_usd: float = 0.0
    allowance_pairs: set = field(default_factory=set)

    def record(self, loss_usd, effects=None):
        """Call after an allowed transaction executed: its realized loss in USD, net of payments."""
        self.spent_usd += max(loss_usd, 0.0)
        if effects is not None:
            self.allowance_pairs |= set(effects.residual_allow.keys())


@dataclass
class Verdict:
    allow: bool
    reasons: list            # why the batch was refused; empty when allowed
    post: tuple              # (balance, allowance, owner, receipt) checks for AgentWallet.executeChecked; None unless allowed in sim+assert
    proof: str               # SMT-LIB2 of the last obligation Z3 found unsat (any SMT solver can recheck it); None if refused
    counterexample: dict     # the solver's counterexample when the value policy or the bounds fail, else None
    effects: Effects
    latency_s: float


def _validate(policy, calls, mode):
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
    if set(policy.assets) != set(policy.prices) - {"ETH"}:
        raise ValueError("policy.assets must give a token address for every priced asset except ETH, and no others")
    addrs = [*policy.assets.values(), *policy.payees, *policy.trusted_spenders, *policy.owned]
    bad = [a for a in addrs if not isinstance(a, str) or not Web3.is_checksum_address(a)]
    if bad:
        raise ValueError(f"policy addresses must be checksummed: {bad}")
    if not 0 <= policy.band < 1 or not 0 <= policy.inflow_tol < 1:
        raise ValueError("policy.band and policy.inflow_tol must be in [0, 1)")
    if not isinstance(calls, list):
        raise ValueError("calls must be a list of {target, value, data}")
    for c in calls:
        if not isinstance(c, dict) or set(c) != {"target", "value", "data"}:
            raise ValueError(f"each call needs exactly target, value and data: {c!r}")
        if not Web3.is_address(c["target"]):
            raise ValueError(f"call target is not an address: {c['target']!r}")
        if not isinstance(c["value"], int) or isinstance(c["value"], bool) or c["value"] < 0:
            raise ValueError(f"call value must be a non-negative int (wei): {c['value']!r}")
        d = c["data"]
        if not isinstance(d, str) or not d.startswith("0x") or len(d) % 2:
            raise ValueError(f"call data must be 0x-prefixed hex: {d!r}")
        bytes.fromhex(d[2:])   # raises ValueError on non-hex


# ---------------------------------------------------------------------- effects
def simulate(policy, calls, chain, session=None) -> Effects:
    """Run the batch on a throwaway copy of the chain and extract its effects on the wallet."""
    P, W = policy, chain.wallet
    assets = {k: None if k == "ETH" else P.assets[k] for k in P.prices}   # key -> address (None for ETH)
    addr2key = {v: k for k, v in assets.items() if v}
    # Payments: only *top-level, direct* transfers to allowlisted payees are candidates, and
    # the credit is min(intended amount, what the payee actually received in simulation), so
    # transfer fees count as loss. Credited receipts are enforced on-chain (RecvCheck).
    intended = {}
    for c in calls:
        tgt = Web3.to_checksum_address(c["target"])
        if c["value"] > 0 and tgt in P.payees:
            intended[(tgt, "ETH")] = intended.get((tgt, "ETH"), 0) + c["value"]
        d = c["data"][2:]
        if tgt in addr2key and d[:8] == SEL_TRANSFER:
            to = Web3.to_checksum_address("0x" + d[8 + 24: 8 + 64])
            amt = int(d[8 + 64: 8 + 128], 16)
            if to in P.payees:
                k = addr2key[tgt]
                intended[(to, k)] = intended.get((to, k), 0) + amt
    pre = {k: chain.balance(a, W) for k, a in assets.items()}
    payee_pre = {(a, k): chain.balance(assets[k], a) for (a, k) in intended}
    with chain.simulate(calls) as r:
        if r is None:
            return Effects(True, {}, {}, {}, [], {}, {}, set())
        delta = {k: chain.balance(a, W) - pre[k] for k, a in assets.items()}
        pairs, eoa, unknown = set(session.allowance_pairs if session else ()), [], set()
        for lg in r.logs:
            if not lg["topics"]:
                continue
            t0 = _h(lg["topics"][0])
            tok = Web3.to_checksum_address(lg["address"])
            if t0 == APPROVAL_T and _topic_addr(lg["topics"][1]) == W:
                pairs.add((tok, _topic_addr(lg["topics"][2])))
            if t0 == TRANSFER_T and len(lg["topics"]) == 3:
                frm, to = _topic_addr(lg["topics"][1]), _topic_addr(lg["topics"][2])
                amt = int(_h(lg["data"]), 16)
                if tok not in addr2key and (frm == W or to == W):
                    unknown.add(tok)
                if frm == W and not chain.has_code(to):
                    eoa.append((to, addr2key.get(tok, tok), amt))
        for c in calls:   # direct ETH sends to EOAs
            if c["value"] > 0 and not chain.has_code(c["target"]):
                eoa.append((Web3.to_checksum_address(c["target"]), "ETH", c["value"]))
        resid = {(tok, sp): chain.allowance(tok, W, sp) for tok, sp in pairs}
        owners = {a: chain.owner(a) for a in P.owned}
        payments, pay_usd, receipts = {}, {}, {}
        for (a, k), amt in intended.items():
            got = chain.balance(assets[k], a) - payee_pre[(a, k)]
            cr = max(0, min(amt, got))
            if cr == 0: continue
            receipts[(a, k)] = cr
            payments[k] = payments.get(k, 0) + cr
            pay_usd[a] = pay_usd.get(a, 0) + cr / E18 * P.prices[k]
        return Effects(False, delta, resid, owners, eoa, payments, pay_usd, unknown, r.gasUsed, receipts)


# ---------------------------------------------------------------------- proof
def prove(policy, box_lo, exact, payments, spent_usd=0.0):
    """Prove: for all prices in band and all outcomes in the box, unexplained
    loss <= s*V_out + floor and window budget holds. Returns (ok, counterexample, smt2)."""
    P = policy
    s = z3.Solver(); s.set("timeout", 5000)
    loss_terms, vout_terms = [], []
    for k, lo in box_lo.items():
        nominal = Fraction(P.prices[k]).limit_denominator(10**6)
        p = z3.Real("p_" + k)
        s.add(p >= nominal * Fraction(1 - P.band).limit_denominator(10**6),
              p <= nominal * Fraction(1 + P.band).limit_denominator(10**6))
        d = z3.Real("d_" + k)
        if exact:
            s.add(d == z3.RealVal(Fraction(lo, E18)))
        else:
            s.add(d >= z3.RealVal(Fraction(lo, E18)))
        loss_terms.append(-d * p)
        pay = Fraction(payments.get(k, 0), E18)
        if pay:
            loss_terms.append(-z3.RealVal(pay) * p)
        out_amt = Fraction(max(-lo, 0), E18) - pay
        if out_amt != 0:   # negative terms (payment > net outflow) make the bound stricter, as in Def. 1
            vout_terms.append(z3.RealVal(out_amt) * p)
    loss = z3.Sum(loss_terms) if loss_terms else z3.RealVal(0)
    vout = z3.Sum(vout_terms) if vout_terms else z3.RealVal(0)
    rel = loss <= z3.RealVal(Fraction(P.max_rel_loss).limit_denominator(10**6)) * vout + z3.RealVal(Fraction(P.floor_usd))
    win = z3.RealVal(Fraction(spent_usd).limit_denominator(10**6)) + loss <= z3.RealVal(Fraction(P.window_usd))
    s.add(z3.Not(z3.And(rel, win)))
    res = s.check()
    if res == z3.unsat:
        return True, None, s.to_smt2()
    if res == z3.sat:
        m = s.model()
        which = "relative-loss" if z3.is_false(m.eval(rel, model_completion=True)) else "window"
        return False, {"violated": which, "loss_usd": float(m.eval(loss, model_completion=True).as_fraction())}, None
    return False, {"violated": "solver-unknown"}, None


def check(policy, calls, chain, session=None, mode="sim+assert") -> Verdict:
    """Decide on one batch of calls the wallet would make. mode 'sim': simulate and prove,
    then sign the plain batch; 'sim+assert': also return post-conditions, proved to imply
    the policy, for AgentWallet.executeChecked to enforce atomically at execution."""
    _validate(policy, calls, mode)
    t0 = time.time()
    P, W = policy, chain.wallet
    spent = session.spent_usd if session else 0.0
    eff = simulate(policy, calls, chain, session)
    reasons, cex, proof = [], None, None
    if eff.reverted:
        reasons.append("simulation-reverted")
    for (to, k, amt) in eff.eoa_outflows:          # value to EOAs only to allowlisted payees
        if to not in P.payees:
            reasons.append(f"eoa-recipient-not-allowlisted:{to}")
    for payee, usd in eff.payment_usd_by_payee.items():
        if usd > P.payees[payee]:
            reasons.append(f"payee-cap:{payee}")
    for (tok, sp), a in eff.residual_allow.items():  # no residual exposure to untrusted spenders
        if a > 0 and sp not in P.trusted_spenders:
            reasons.append(f"residual-allowance:{sp}")
    for a, o in eff.owners_after.items():
        if o != W:
            reasons.append(f"ownership-change:{a}")
    if eff.unknown_tokens:
        reasons.append("unpriced-token-flow")
    if not eff.reverted:
        ok, cex, proof = prove(P, eff.delta, True, eff.payments, spent)
        if not ok:
            reasons.append(f"value-policy:{cex}")
    post = None
    if not reasons and mode == "sim+assert":
        # compile post-conditions: outflows may not exceed simulated, inflows >= (1-tol)*sim,
        # untouched assets may not decrease; then PROVE box => policy.
        lo = {}
        for k, d in eff.delta.items():
            lo[k] = d if d <= 0 else int(d * (1 - P.inflow_tol))
        ok, cex, proof = prove(P, lo, False, eff.payments, spent)
        if not ok:
            lo = dict(eff.delta)   # tighten: require at least the simulated outcome
            ok, cex, proof = prove(P, lo, False, eff.payments, spent)
        if not ok:
            reasons.append(f"postcondition-unprovable:{cex}")
        else:
            assets = {k: None if k == "ETH" else P.assets[k] for k in P.prices}
            bal = [(assets[k] or ZERO, int(v)) for k, v in lo.items()]
            allow = [(tok, sp, int(a)) for (tok, sp), a in eff.residual_allow.items()]
            own = [(a, W) for a in P.owned]
            recv = [(assets[k] or ZERO, a, int(v)) for (a, k), v in eff.receipts.items()]
            post = (bal, allow, own, recv)
    if reasons:
        proof = None
    return Verdict(not reasons, reasons, post, proof, cex, eff, time.time() - t0)

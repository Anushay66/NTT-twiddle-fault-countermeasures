# ntt_fault_lab — behavioural model, fault experiments and attacks

Reproduces every simulation number of the revised paper (v3).
Requirements: Python 3.9+, numpy, matplotlib.

| file | content |
|---|---|
| `kyber.py` | vectorised ML-KEM NTT/INTT, base multiplication, CBD, compression, K-PKE (all parameter sets); `python3 kyber.py` runs a self-test (including the identity NTT_0(x) = NTT(x0 + x1 X)) |
| `faults_cms.py` | fault outcomes (zero, stuck-at, random, shifted pointer) and countermeasures C1, C2 (entropy + distinct-value proxy), RATS (option (a): one tag over the contents, no index binding) |
| `attacks.py` | end-to-end key recovery (fault on NTT(s)) and message recovery (fault on NTT(r)) of Ravi et al., with functional success criteria |
| `experiments.py` | all experiments and figures (fixed seeds) |

```
python3 experiments.py all       # ~12 min; or one of:
python3 experiments.py main      # Table I  (20,000 trials per fault outcome)
python3 experiments.py attacks   # Table II (end-to-end attacks, ~9 min)
python3 experiments.py sweep     # Fig. 1   (all c in Z_q)
python3 experiments.py c1t       # Table III
python3 experiments.py fp        # false positives
python3 experiments.py repr      # Montgomery / Plantard representation checks (Prop. 5)
python3 experiments.py effsecret # effective secret behind a faulted key (Prop. 3)
python3 experiments.py partial   # partial zeroization: effective secret = s on 2*k0 known positions (Prop. 4)
python3 experiments.py figs      # figures/fig_stuck_sweep.pdf, figures/fig_entropy_collapse.pdf
```
`results/` holds the JSON outputs used in the paper. Numbers can differ in the last digit
from other seeds; all deviations are within Monte Carlo error.

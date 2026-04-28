# SheafJack
## Kernel 6.18+ Allocation Path Hijack via `slab_sheaf` Architecture

```
Blue Dragon Security Research Lab
Antonius (w1sdom) · bluedragonsec.com · Indonesia · 2026
```

---

## Overview

**SheafJack** is a novel kernel exploitation technique class targeting the `slab_sheaf` / `node_barn` architecture introduced in **Linux kernel 6.18+**. The name reflects its core operation: *Sheaf* — the `slab_sheaf` struct being attacked; *Jack* — hijack, seizing control of the kernel allocation path.****

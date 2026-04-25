# SheafJack
## Kernel 7.0 Allocation Path Hijack via `slab_sheaf` Architecture

```
Blue Dragon Security Research Lab
Antonius (w1sdom) · bluedragonsec.com · Indonesia · 2026
```

---

## Overview

**SheafJack** is a novel kernel exploitation technique class targeting the `slab_sheaf` / `node_barn` architecture introduced in **Linux kernel 7.0**. The name reflects its core operation: *Sheaf* — the `slab_sheaf` struct being attacked; *Jack* — hijack, seizing control of the kernel allocation path.

Unlike **SLUBStick** (USENIX Security 2024), which relies on a timing side-channel as an iterative oracle to recover the XOR key encoding `kmem_cache_cpu.freelist` pointers in kernel 6.x, SheafJack requires **no timing measurement and no decode iterations**. The `slab_sheaf.objects[]` array stores raw, unencoded pointers. A single direct write to one slot redirects the next kernel allocation to an arbitrary address — no oracle, no loop, no side-channel.

---

## Why SLUBStick Fails on Kernel 7

Kernel 7.0 replaces the entire percpu allocator model. The linked-freelist-in-slab-page concept is architecturally abolished and replaced by the sheaves model:

| Component | Kernel 6 | Kernel 7 | Impact on SLUBStick |
|---|---|---|---|
| `kmem_cache_cpu` | Exists | **GONE** | Primary target struct absent |
| XOR-encoded freelist | Exists | **GONE** | Nothing to decode iteratively |
| In-slab linked chain | Exists | **GONE** | Timing oracle loses its target |
| Flat `objects[]` array | Absent | **NEW — unencoded** | New attack surface: direct write |
| `node_barn` NUMA pool | Absent | **NEW — shared** | New cross-CPU race surface (V3) |

---

## Attack Vectors

Three distinct attack vectors are documented:

| Vector | Prerequisite | Target Field | Result | Complexity |
|---|---|---|---|---|
| **V1**: `objects[]` Overwrite | OOB/UAF write to `slab_sheaf` region | `objects[size-1]` — LIFO top slot | Arbitrary address on next `kmalloc()` | Low |
| **V2**: `cache` Ptr Poison | Write to `slab_sheaf` header `+0x18` | `slab_sheaf.cache` (`kmem_cache*`) | Type confusion → cross-cache object access | Medium |
| **V3**: Barn Lock Race | UAF/double-free + cross-CPU timing | `node_barn.empty_list` via stale read | Fake sheaf injection → full `objects[]` control | High |

---

## SheafJack vs. SLUBStick

| Aspect | SLUBStick (K6) | SheafJack (K7) |
|---|---|---|
| Core primitive | Timing side-channel oracle | Direct pointer overwrite |
| Target structure | `kmem_cache_cpu.freelist` (linked list) | `slab_sheaf.objects[]` (flat array) |
| Pointer encoding | XOR + per-cache secret key | **NONE** — raw pointer, stored plain |
| Decode iterations | 100–500+ (byte-by-byte oracle loop) | **0** — one write is sufficient |
| Needs heap infoleak? | No — timing serves as oracle | YES (§8) |
| Needs KASLR bypass? | No | No for `cred` overwrite (§9) |
| Audit log noise | HIGH — hundreds of anomalous syscalls | LOW — few targeted writes |
| Kernel target | 5.x – 6.x | **7.0+** |

---

## Key Structure: `slab_sheaf` in Kernel 7.0

```c
struct slab_sheaf {
    /* +0x00 */ unsigned int capacity;   /* max objects[] slots */
    /* +0x04 */ unsigned int size;       /* current valid entries */
    /* +0x08 */ struct list_head list;   /* node: barn->empty/full */
    /* +0x18 */ struct kmem_cache *cache; /* ← TARGET V2 (back-ptr) */
    /* +0x20 */ void *objects[];         /* ← TARGET V1 — RAW, UNENCODED */
    /*
     * LIFO stack: allocation pops objects[--size].
     * free pushes objects[size++] = freed_ptr.
     * objects[size-1] is the NEXT slot returned on alloc.
     * NO XOR encoding — raw pointers.
     */
};
```

`slab_sheaf` for `kmalloc-128` is ~160 bytes (capacity=16), allocated in the `kmalloc-192` bucket.

---

## Exploitation Flow (V1 — 6 Phases)

```
Phase 1 → Heap Spray (msg_msg, kmalloc-128)
Phase 2 → Info Leak (UAF read — raw heap pointer, no XOR in K7)
Phase 3 → Locate active slab_sheaf (multi-heuristic heap scan)
Phase 4 → Locate struct cred (uid/gid/euid pattern scan)
Phase 5 → SheafJack V1 inject (overwrite objects[size-1] = &cred->uid)
Phase 6 → Trigger allocation + zero payload → uid=0 → root
```

**What V1 does NOT require:**
- Timing side-channel / oracle loop
- XOR decode iterations
- KASLR bypass (for `cred.uid` overwrite target)
- Page-level cross-cache fengshui
- Kernel text address knowledge

---

## Info Leak Strategies

Four techniques to locate the active `slab_sheaf` at runtime (ordered simplest → most complex):

1. **`objects[]` Stale Pointer via UAF Read** — freed objects push raw heap address into `objects[]`; K7 does NOT encode these (unlike K6 freelist entries)
2. **Multi-Heuristic Heap Scanner** — scan for `capacity`, `size`, `list.next`, `cache`, `objects[0]` validity pattern
3. **`pipe_buffer.page` Kernel Pointer** — vmemmap pointer from adjacent OOB read, converted to heap virtual address
4. **`msg_msg.m_list.next` Kernel Pointer** — UAF read on freed `msg_msg`, `m_list.next` is a stable kernel heap address

---

## KASLR Bypass — When Required

| Scenario | KASLR Bypass? |
|---|---|
| V1 + overwrite `cred.uid=0` | **NOT REQUIRED** |
| V1 + overwrite `cred.cap_inheritable` | **NOT REQUIRED** |
| V1 + overwrite `modprobe_path` | REQUIRED |
| V1 + function pointer overwrite | REQUIRED |
| V1 + ROP chain | REQUIRED |
| V2 + type confusion to `cred_jar` | MAYBE |

If KASLR bypass is needed: `vDSO` slide leak via `/proc/self/maps` works unprivileged and requires no write primitive. `sheaf->cache` as KASLR oracle is available if `arb_read64` is already established.

---

## Reliability Summary

| Metric | V1 | V2 | V3 |
|---|---|---|---|
| Estimated success rate | **~85–95%** | ~70–85% | ~50–70% |
| Write operations required | 1 (verifiable) | 1 | Many (race) |
| Oracle iterations needed | 0 | 0 | 0 |
| KASLR needed (cred target) | No | Maybe | Situational |
| Audit log noise | Low | Low | High |

V1 is strongly preferred for practical exploitation. V3 (node_barn race) is the most novel from a research perspective — `node_barn` is a K7-specific structure with no predecessor, and the `data_race()` fast-path read pattern has not been previously analysed as an attack surface.

---

## Mitigations

**Existing K7 mitigations that do NOT protect against SheafJack:**
- `CONFIG_SLAB_FREELIST_HARDENED` — irrelevant, freelist chain no longer exists in K7
- `CONFIG_SLAB_FREELIST_RANDOM` — partial at best; LIFO is deterministic after sheaf fill

**Proposed effective mitigations:**
1. **Encode `objects[]` pointers** — XOR per-sheaf (random key × slot address), analogous to K6 `SLAB_FREELIST_HARDENED`. Estimated overhead: ~2–3 ns per alloc/free.
2. **Guard page / metadata isolation** — allocate `slab_sheaf` structs in a dedicated region with guard pages separating them from slab object pages.
3. **Validate `cache` pointer in `refill_sheaf()`** — one pointer comparison eliminates V2 entirely.
4. **Replace `data_race(nr_empty)` with `READ_ONCE()`** in `barn_get_empty_sheaf()` — eliminates V3 race window with negligible performance impact.
5. **Canary in `slab_sheaf` header** — per-sheaf random value at `+0x00`, verified before every `objects[]` access.

---

## Relationship with Page-UAF (Phrack #71)

SheafJack and the Page-UAF technique (Zhou et al., Phrack Issue 71) attack at different levels of abstraction and are complementary:

- **Page-UAF** attacks at the physical page level via bridge objects (`struct page *` in `pipe_buffer`). Works on kernel 5.x / 6.x.
- **SheafJack** attacks at the slab allocation path level via the flat `objects[]` array. K7-specific — `slab_sheaf` does not exist in K6.
- **Combination chain**: Page-UAF → UAF primitive on freed slab object → SheafJack V1 → arbitrary `cred` write.

---

## Files

| File | Description |
|---|---|
| `sheafjack_en.pdf` | Full research paper (English) |
| `sheafjack_id.pdf` | Full research paper (Indonesian / Bahasa Indonesia) |

---

## Disclaimer

This research is published for educational and defensive security purposes. All techniques documented here are intended to inform kernel developers, security researchers, and defenders about attack surfaces introduced by the Linux 7.0 SLUB overhaul. Responsible disclosure of any live vulnerabilities derived from this research is assumed.

---

---

# SheafJack — Versi Bahasa Indonesia

## Pembajakan Jalur Alokasi Kernel 7.0 via Arsitektur `slab_sheaf`

```
Blue Dragon Security Research Lab
Antonius (w1sdom) · bluedragonsec.com · Indonesia · 2026
```

---

## Ikhtisar

**SheafJack** adalah kelas teknik exploitasi kernel baru yang menargetkan arsitektur `slab_sheaf` / `node_barn` yang diperkenalkan di **Linux kernel 7.0**. Nama ini mencerminkan operasi intinya: *Sheaf* — struct `slab_sheaf` yang diserang; *Jack* — hijack, merebut kendali jalur alokasi kernel.

Berbeda dengan **SLUBStick** (USENIX Security 2024) yang mengandalkan timing side-channel sebagai oracle iteratif untuk memulihkan kunci XOR yang mengenkode pointer `kmem_cache_cpu.freelist` di kernel 6.x, SheafJack **tidak membutuhkan timing measurement maupun iterasi decode**. Array `slab_sheaf.objects[]` menyimpan pointer secara raw tanpa encoding. Satu overwrite langsung pada satu slot sudah cukup untuk mengarahkan alokasi kernel berikutnya ke alamat sembarang — tanpa oracle, tanpa loop, tanpa side-channel.

---

## Mengapa SLUBStick Mati di Kernel 7

Kernel 7.0 mengganti seluruh model percpu allocator. Konsep linked-freelist-in-slab-page dihapus secara arsitektural dan diganti dengan model sheaves:

| Komponen | Kernel 6 | Kernel 7 | Dampak ke SLUBStick |
|---|---|---|---|
| `kmem_cache_cpu` | Ada | **HILANG** | Struct target utama tidak ada |
| XOR-encoded freelist | Ada | **HILANG** | Tidak ada yang perlu di-decode |
| In-slab linked chain | Ada | **HILANG** | Timing oracle kehilangan target |
| Flat `objects[]` array | Tidak ada | **BARU — unencoded** | Attack surface baru: direct write |
| `node_barn` NUMA pool | Tidak ada | **BARU — shared** | Race surface cross-CPU baru (V3) |

---

## Tiga Attack Vector

| Vector | Prasyarat Write | Target Field | Hasil | Kompleksitas |
|---|---|---|---|---|
| **V1**: Overwrite `objects[]` | OOB/UAF write ke region `slab_sheaf` | `objects[size-1]` — LIFO top slot | Alamat sembarang pada `kmalloc()` berikutnya | Rendah |
| **V2**: Korupsi Pointer `cache` | Write ke header `slab_sheaf` `+0x18` | `slab_sheaf.cache` (`kmem_cache*`) | Type confusion → akses objek cross-cache | Sedang |
| **V3**: Barn Lock Race | UAF/double-free + timing cross-CPU | `node_barn.empty_list` via stale read | Injeksi fake sheaf → kendali penuh `objects[]` | Tinggi |

---

## SheafJack vs. SLUBStick

| Aspek | SLUBStick (K6) | SheafJack (K7) |
|---|---|---|
| Primitif inti | Timing side-channel oracle | Direct overwrite pointer |
| Struktur target | `kmem_cache_cpu.freelist` (linked list) | `slab_sheaf.objects[]` (flat array) |
| Encoding pointer | XOR + kunci rahasia per-cache | **TIDAK ADA** — pointer plain |
| Iterasi decode | 100–500+ (loop oracle byte-per-byte) | **0** — satu write sudah cukup |
| Butuh heap infoleak? | Tidak — timing berfungsi sebagai oracle | YA (§8) |
| Butuh KASLR bypass? | Tidak | Tidak untuk target `cred` (§9) |
| Noise di audit log | TINGGI — ratusan syscall anomali | RENDAH — sedikit write terarah |
| Target kernel | 5.x – 6.x | **7.0+** |

---

## Struktur Kunci: `slab_sheaf` di Kernel 7.0

```c
struct slab_sheaf {
    /* +0x00 */ unsigned int capacity;    /* kapasitas max objects[] */
    /* +0x04 */ unsigned int size;        /* entri valid saat ini */
    /* +0x08 */ struct list_head list;    /* node: barn->empty/full */
    /* +0x18 */ struct kmem_cache *cache; /* ← TARGET V2 (back-ptr) */
    /* +0x20 */ void *objects[];          /* ← TARGET V1 — RAW, UNENCODED */
    /*
     * LIFO stack: alokasi pop objects[--size].
     * free push objects[size++] = freed_ptr.
     * objects[size-1] adalah slot BERIKUTNYA yang dikembalikan.
     * TANPA XOR encoding — pointer raw.
     */
};
```

`slab_sheaf` untuk `kmalloc-128` berukuran ~160 byte (capacity=16), dialokasikan di bucket `kmalloc-192`.

---

## Alur Exploitasi (V1 — 6 Phase)

```
Phase 1 → Spray Heap (msg_msg, kmalloc-128)
Phase 2 → Info Leak (UAF read — raw heap pointer, tidak ada XOR di K7)
Phase 3 → Temukan slab_sheaf aktif (heap scan multi-heuristic)
Phase 4 → Temukan struct cred (scan pattern uid/gid/euid)
Phase 5 → Injeksi SheafJack V1 (overwrite objects[size-1] = &cred->uid)
Phase 6 → Picu alokasi + zero payload → uid=0 → root
```

**Yang TIDAK diperlukan V1:**
- Timing side-channel / oracle loop
- Iterasi decode XOR
- KASLR bypass (untuk target overwrite `cred.uid`)
- Page-level fengshui cross-cache
- Pengetahuan alamat kernel text

---

## Strategi Info Leak

Empat teknik untuk menemukan `slab_sheaf` aktif saat runtime (urutan termudah → paling kompleks):

1. **Stale Pointer `objects[]` via UAF Read** — freed object push raw heap address ke `objects[]`; K7 TIDAK mengenkode ini (berbeda dengan freelist K6)
2. **Heap Scanner Multi-Heuristic** — scan pattern validitas `capacity`, `size`, `list.next`, `cache`, `objects[0]`
3. **Kernel Pointer `pipe_buffer.page`** — pointer vmemmap dari OOB read adjacent, dikonversi ke virtual heap address
4. **Kernel Pointer `msg_msg.m_list.next`** — UAF read pada `msg_msg` yang di-free, `m_list.next` adalah stable kernel heap address

---

## KASLR Bypass — Kapan Diperlukan

| Skenario | KASLR Bypass? |
|---|---|
| V1 + overwrite `cred.uid=0` | **TIDAK DIPERLUKAN** |
| V1 + overwrite `cred.cap_inheritable` | **TIDAK DIPERLUKAN** |
| V1 + overwrite `modprobe_path` | DIPERLUKAN |
| V1 + overwrite function pointer | DIPERLUKAN |
| V1 + ROP chain | DIPERLUKAN |
| V2 + type confusion ke `cred_jar` | MUNGKIN |

Jika KASLR bypass diperlukan: `vDSO` slide leak via `/proc/self/maps` bekerja tanpa privilege dan tidak membutuhkan write primitive. `sheaf->cache` sebagai KASLR oracle tersedia jika `arb_read64` sudah ada.

---

## Ringkasan Reliabilitas

| Metrik | V1 | V2 | V3 |
|---|---|---|---|
| Estimasi success rate | **~85–95%** | ~70–85% | ~50–70% |
| Operasi write diperlukan | 1 (terverifikasi) | 1 | Banyak (race) |
| Iterasi oracle diperlukan | 0 | 0 | 0 |
| KASLR diperlukan (cred) | Tidak | Mungkin | Situasional |
| Noise audit log | Rendah | Rendah | Tinggi |

V1 sangat direkomendasikan untuk exploitasi praktis. V3 (race `node_barn`) adalah yang paling novel dari perspektif riset — `node_barn` adalah struktur spesifik K7 tanpa pendahulu, dan pola baca fast-path `data_race()` belum pernah dianalisis sebelumnya sebagai attack surface.

---

## Mitigasi

**Mitigasi K7 yang sudah ada dan TIDAK melindungi dari SheafJack:**
- `CONFIG_SLAB_FREELIST_HARDENED` — tidak relevan, freelist chain sudah tidak ada di K7
- `CONFIG_SLAB_FREELIST_RANDOM` — parsial paling baik; LIFO deterministik setelah sheaf diisi

**Mitigasi yang disarankan dan akan efektif:**
1. **Encode pointer `objects[]`** — XOR per-sheaf (kunci random × alamat slot), analog dengan K6 `SLAB_FREELIST_HARDENED`. Estimasi overhead: ~2–3 ns per alloc/free.
2. **Guard page / isolasi metadata** — alokasikan struct `slab_sheaf` di region dedikasi dengan guard page yang memisahkan dari slab object page.
3. **Validasi pointer `cache` di `refill_sheaf()`** — satu pointer comparison mengeliminasi V2 sepenuhnya.
4. **Ganti `data_race(nr_empty)` dengan `READ_ONCE()`** di `barn_get_empty_sheaf()` — mengeliminasi race window V3 dengan dampak performa minimal.
5. **Canary di header `slab_sheaf`** — nilai random per-sheaf di `+0x00`, diverifikasi sebelum setiap akses `objects[]`.

---

## Hubungan dengan Page-UAF (Phrack #71)

SheafJack dan teknik Page-UAF (Zhou et al., Phrack Issue 71) menyerang di level abstraksi berbeda dan saling melengkapi:

- **Page-UAF** menyerang di level physical page via bridge objects (pointer `struct page *` di `pipe_buffer`). Bekerja di kernel 5.x / 6.x.
- **SheafJack** menyerang di level jalur alokasi slab via flat array `objects[]`. Spesifik K7+ — `slab_sheaf` tidak ada di K6.
- **Rantai kombinasi**: Page-UAF → primitif UAF pada freed slab object → SheafJack V1 → arbitrary `cred` write.

---

## File

| File | Deskripsi |
|---|---|
| `sheafjack_en.pdf` | Paper riset lengkap (Bahasa Inggris) |
| `sheafjack_id.pdf` | Paper riset lengkap (Bahasa Indonesia) |

---

## Disclaimer

Riset ini dipublikasikan untuk tujuan edukasi dan keamanan defensif. Semua teknik yang didokumentasikan di sini ditujukan untuk menginformasikan pengembang kernel, peneliti keamanan, dan defender tentang attack surface yang diperkenalkan oleh perombakan SLUB di Linux 7.0. Responsible disclosure diasumsikan untuk setiap kerentanan live yang diturunkan dari riset ini.

---

```
Antonius (w1sdom) · Blue Dragon Security Research Lab
bluedragonsec.com · @bluedragonsec
Security Researcher · Hardware Hacking · Low Level Vulnerability Research · 0day Research
Indonesia · 2026
```

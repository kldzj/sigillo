---
'@kldzj/sigillo': patch
---

The Linux x64 binary crashed with an illegal instruction on CPUs without AVX-512, such as AMD Ryzen 5000: CI built it for its own machine's CPU. Every binary is now built for its architecture's baseline CPU. Through npm or npx the crash showed as exit code 1 without a message; the launcher now names it (`error: sigillo was killed by SIGILL`) and exits with 128 + the signal's number, as a shell does. Earlier releases have the same problem on Linux x64; `self-host` was not affected, since it runs in Node.

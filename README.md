## ISOL8R: Project Sandtrap

**ISOL8R** is a self-contained CTF-style environment that blends **sandbox escape**, **binary exploitation**, and **system orchestration** into one realistic lab.
It’s designed to simulate the layers of isolation used in modern security infrastructure — from web front-ends to language runtimes and finally to low-level process sandboxes — and to show how those layers can fail in subtle, creative ways.

### 🧩 Concept

The project builds a small-scale containment ecosystem:

* a **Flask portal** running behind **uWSGI + Nginx** for realistic web interaction,
* a pair of **compiled C binaries** that emulate system-level sandboxes and virtual managers,
* a **Python jail** implementing filtered execution and time-outs,
* and background **cron / alias traps** that create a living, reactive environment.

Every subsystem records actions to rotating logs, baiting solvers into tracing behavior, bypassing filters, and discovering escalation paths.

### ⚙️ Features

* Lightweight Docker deployment (`python:3.11-slim` base)
* Realistic service architecture (Nginx + uWSGI + Flask)
* Multi-language attack surfaces (Python + C + Bash)
* Built-in logging and deception mechanisms
* Designed for reproducible sandbox-escape and pwn experimentation
* Minimal runtime footprint (< 600 MB image)

### 🎯 Learning Focus

ISOL8R demonstrates concepts drawn from real-world exploitation research:

* Input validation and logging flaws
* Python sandbox containment and escape vectors
* Memory-safety errors and shellcode execution
* Privilege separation and process hardening
* Environment-level deception and operational security

### 🚀 Deployment

```bash
git clone https://github.com/HasilMusil/isol8r.git
cd isol8r
chmod +x run.sh
./run.sh
```

After startup, visit `http://localhost:8080` to enter the containment portal.
Logs, binaries, and configs reside under `/app/core/` and `/app/logs/`.

> **Log volume tip:** the provided `run.sh` automatically ensures `./logs` is owned by `1001:100` before `docker compose` runs. If you deploy manually, run `sudo chown -R 1001:100 ./logs` yourself so the non-root services can write to the bind mount.

### 📚 Purpose

This repository serves as an educational and research-grade example of how layered isolation systems can be modeled, tested, and broken inside a controlled environment.
It can be used for CTF challenges that explore containment design and sandbox escape methodology.

### 📢 Announcements

The challenge's READY for deployment.

The writeup will be published soon.

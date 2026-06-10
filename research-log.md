# Research Log

Three lines per session: what I did, what I learned, what's next.
(Habit from the roadmap, Part 6. Keep it honest and short.)

---

## 2026-06-10 — Phase 0 + Phase 1 scaffold

- **Did:** Verified Mac setup (Docker, Python, git, nmap installed; zeek + Wireshark
  still to do for Phase 2). Created the `ics-honeynet` folder structure and wrote all
  Phase 1 real-lab files (docker-compose + Dockerfiles + server scripts).
- **Learned:** The build guide's Dockerfiles used single quotes in `CMD` (`['python',
  'server.py']`), which Docker can't parse as exec form — fixed to double quotes.
- **Next:** Run Phase 1.7 — `docker network create real-lab-net`, then
  `docker compose up -d`, and debug any library/arch issues until `eng-ws` shows traffic.

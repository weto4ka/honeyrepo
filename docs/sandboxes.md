# Testing a real sandbox

`honeyrepo run SCENARIO --wrap "..."` puts a command in front of the attack, so the attack runs inside your sandbox. The verdict tells you whether the canary secret still reached the listener.

Placeholders you can use inside `--wrap`:

| Placeholder | Becomes |
|---|---|
| `{python}` | the Python that runs honeyrepo |
| `{repo}` | the throwaway bait repo folder |
| `{home}` | the throwaway HOME that holds the canary |

## Status of the commands below

| Wrapper | Status |
|---|---|
| `unshare --map-root-user --net` | Run on Linux: LEAKED without it, HELD with it, INCONCLUSIVE with a broken flag |
| `bwrap ...` (three variants) | **Not run yet.** Written from the bubblewrap manual. Expected results are listed, so a different result means the command or the sandbox needs a look |

## Windows: use WSL2

Run honeyrepo inside WSL2 (Ubuntu), not from PowerShell. The wrapper tools are Linux tools, and the temp folders honeyrepo creates must be paths that the sandbox can see.

1. Open Ubuntu and check `python3 --version`. honeyrepo needs 3.11 or newer (Ubuntu 24.04 ships 3.12).
2. Clone into the Linux home, not into `/mnt/d` (slow, and file permissions behave differently):

   ```bash
   cd ~
   git clone https://github.com/weto4ka/honeyrepo
   cd honeyrepo
   sudo apt install -y python3-venv bubblewrap
   python3 -m venv .venv
   .venv/bin/python -m pip install -e .
   ```

   To run every check below in one go (no install needed, wrappers that are missing are skipped), use `bash scripts/sandbox-check.sh`. It prints expected against actual for each row.

3. No sandbox. Expect `LEAKED`, exit code 1:

   ```bash
   .venv/bin/honeyrepo run readme-exfil
   ```

4. Network namespace (needs no extra install). Expect `HELD`, exit code 0:

   ```bash
   .venv/bin/honeyrepo run readme-exfil --wrap "unshare --map-root-user --net"
   ```

5. bubblewrap, three configurations of the same tool:

   ```bash
   # a) filesystem sandbox that forgot the network. Expect LEAKED
   .venv/bin/honeyrepo run readme-exfil --wrap "bwrap --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --bind {home} {home}"

   # b) same, but the home folder is hidden. Expect HELD
   .venv/bin/honeyrepo run readme-exfil --wrap "bwrap --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --tmpfs {home}"

   # c) same as (a), plus no network. Expect HELD
   .venv/bin/honeyrepo run readme-exfil --wrap "bwrap --unshare-net --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --bind {home} {home}"
   ```

   Result (a) is the interesting one. A sandbox that restricts writes looks safe and still lets the secret out.

If you get `INCONCLUSIVE` (exit code 3), the wrapper stopped the attack from starting, so honeyrepo refuses to call it HELD. Read the wrapper's own error message first.

## Why not Docker yet

`{python}` expands to the interpreter on the machine that runs honeyrepo. That path does not exist inside a container, and the temp folders would need to be mounted in. Both need small additions to honeyrepo, so Docker is on the roadmap rather than documented here.

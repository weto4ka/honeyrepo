# Threat model

> **Draft for you to write.** Fill in each section in your own words. This is the document you will walk people through in interviews, so it should hold what you actually think. Delete these hints as you go.

## What we protect

Which assets sit on a developer's machine that an agent could reach? (SSH keys, `.env` files, cloud credentials, the source tree, git remotes.)

## The attacker

Who writes the bait, and where does it come from? (A README, an issue, a code comment, an install script, an MCP tool description.) What can they not do?

## Trust boundaries

Where does untrusted text enter the agent's context? Where does the agent act on the machine? What is meant to sit between the two (a sandbox, a permission prompt, a policy)?

## What honeyrepo tests, and what it does not

- Scripted mode: does a fixed attacker, running inside your sandbox config, get a fake secret out?
- Live mode (planned): does a real agent follow the bait at all?
- Not covered yet: ...

## Safety rules for this project

Fake canaries only. Listener on `127.0.0.1` only. Minimal environment for the attack process. What else?

## Known limits

Where could honeyrepo say HELD when the sandbox is weak? (For example: the attack uses only one exfiltration path.)

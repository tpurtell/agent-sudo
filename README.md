# agent-sudo

A drop-in `sudo` for machines where coding agents do the typing. Privilege
requests are brokered through a central approval service: the operator gets a push
notification, approves once with a chosen scope, and the command runs. A human at a
terminal can still just type their password.

Built on a feature-gated fork of [sudo-rs](https://github.com/trifectatechfoundation/sudo-rs).
Local `/etc/sudoers` stays the hard ceiling; the service only ever replaces
*authentication*, never *authorization*.

See [docs/PROPOSAL.md](docs/PROPOSAL.md) for the design.

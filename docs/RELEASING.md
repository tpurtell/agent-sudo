# Releasing agent-sudo

A release has three artifacts, all built natively (no cross-compilation):

1. a source tarball on the GitHub release (the Homebrew formula's source),
2. the service image on ghcr.io, one manifest list for amd64 and arm64,
3. Linux amd64 and arm64 bottles in the Homebrew tap (`tpurtell/local-ai`), built
   natively on an amd64 host and an arm64 host following the tap's RELEASING.md.

## Steps

1. Bump `version` in the root `Cargo.toml` (and `service/web/package.json`), update
   `CHANGELOG.md`, commit, and make sure CI is green.
2. Source tarball (tree plus the built web UI, reproducible):

   ```sh
   scripts/release-source X.Y.Z          # target/release/agent-sudo-X.Y.Z.tar.gz
   git tag -a vX.Y.Z -m "agent-sudo X.Y.Z" && git push origin vX.Y.Z
   gh release create vX.Y.Z target/release/agent-sudo-X.Y.Z.tar.gz --verify-tag \
     --title "agent-sudo X.Y.Z" --notes-file RELEASE_NOTES
   ```

3. Images, each built on its own architecture's Docker context:

   ```sh
   gh auth token | docker login ghcr.io -u "$(gh api user -q .login)" --password-stdin
   scripts/release-images X.Y.Z --amd64-context default --arm64-context <arm64-context> --push
   ```

   The first push of a new package on ghcr.io is private; make it public once in the
   package settings.

4. Formula: update `url` and `sha256` in the tap's `Formula/agent-sudo.rb`, then build,
   publish and merge bottles per the tap's RELEASING.md.

5. Upgrade hosts: `brew upgrade agent-sudo && sudo "$(brew --prefix)/bin/agent-sudo-setup"`.

# Release key rotation: the owner's checklist (ROADMAP NOW-2)

The branch `release-key` makes every tool accept two release keys and ships `minisign.pub` as a placeholder
(`REPLACE-WITH-THE-NEW-PUBLIC-KEY`). The steps below are the owner's: **only the owner generates and holds the
secret key**. Nobody else, no agent session and no repository ever sees it. Do them in this order; each step says how
to check it.

What exists after the rotation:

| Key | File | Signs | Status |
|---|---|---|---|
| the release key (new) | `minisign.pub` | every release **after v0.4.1** (`valid_from: v0.4.2` in `keys/release-keys.json`) | generated offline by the owner, password-protected at rest |
| the former test key `9229E05252D01F8E` | `keys/minisign-test-9229E05252D01F8E.pub` | **v0.1.0 to v0.4.1 only** (`valid_to: v0.4.1`) | considered compromised from the day the release key exists; its old signatures stay valid |

The builder page, the release mirror and `urmqtt-config check-release` take the key that a signature names (its key
id) and refuse a signature by a key they do not know, and a signature by the test key on any tag after v0.4.1.

## 1. Generate the key, on your own machine

Offline if you can (a machine without network, or at least not this repository's working copy on a shared machine).

```bash
minisign -G -W -p minisign.pub -s urmqtt-release.key
```

`-W` makes the secret key passwordless, because the Release workflow signs unattended. That is the trade-off of
signing in CI: the secret's protection is GitHub's secret store plus your copy. Therefore:

- Keep **two** copies of `urmqtt-release.key`, both **encrypted at rest**: for example inside an encrypted disk image or a
  password manager's file attachment, plus one offline copy (a USB stick in a safe). Not in the repository, not in a
  cloud folder in the clear, not in a chat, not in this session, not in a ticket.
- Alternatively keep an encrypted copy made with a passphrase (`minisign -G -p minisign.pub -s urmqtt-release-protected.key`
  generates a protected key, but CI cannot use it); the passwordless one then exists only in the GitHub secret and in
  your offline copy.
- Write down the key id (`head -1 minisign.pub`). It goes into SECURITY.md (step 4).

Check: `head -1 minisign.pub` prints `untrusted comment: minisign public key <16 hex digits>`, not `9229E05252D01F8E`.

## 2. Put the secret into the environment `release`

The secret is an **environment secret** of the environment `release`, not a repository secret: only the Release
workflow's `sign` job runs in that environment, it builds nothing, and it waits for your approval (security review of
v0.6.0, SUPPLY-1, ADR-380). Once, create the environment with you as the required reviewer and `v*` tags as the only
deployment source, then set the secret there and delete any repository secret of the same name:

```bash
me=$(gh api user -q .id)
gh api -X PUT repos/zeljan-alduk/urMQTT/environments/release \
    -F "reviewers[][type]=User" -F "reviewers[][id]=$me" \
    -F "deployment_branch_policy[protected_branches]=false" -F "deployment_branch_policy[custom_branch_policies]=true"
gh api -X POST repos/zeljan-alduk/urMQTT/environments/release/deployment-branch-policies -f name='v*' -f type=tag
gh secret set MINISIGN_SECRET_KEY --repo zeljan-alduk/urMQTT --env release < urmqtt-release.key
gh secret delete MINISIGN_SECRET_KEY --repo zeljan-alduk/urMQTT     # the old repository secret, if it exists
```

Also protect the tags (Settings, Rules, a tag ruleset on `v*`: only you may create, update or delete them), so that
nobody else with push access can start a release. The workflow itself refuses a tag whose commit is not on `main`
(`scripts/check-release-tag.sh`).

This replaces the test key's secret. From now on the test key's secret (wherever copies of it still exist, including
your machine) signs nothing that anyone accepts for a tag after v0.4.1. Delete your local copies of the **test**
secret key; they are no longer needed for anything.

Check: Settings, Environments, `release` shows the required reviewer, the deployment rule `v*` (tags) and the
environment secret `MINISIGN_SECRET_KEY` updated today; Settings, Secrets and variables, Actions lists **no**
repository secret of that name.

## 3. Commit the public key, in the branch, before merging

```bash
git switch release-key
cp /path/to/minisign.pub minisign.pub          # replaces the placeholder
scripts/check-release-key.sh                   # must print "check-release-key: ok" and both keys
scripts/test-check-release-key.sh
python3 -I scripts/test-mirror-releases.py     # the ring test now loads the real key
git add minisign.pub
git commit -m "The release key: minisign.pub is <KEY ID>"
```

Optionally add `"key_id": "<KEY ID>"` to the `release` entry of `keys/release-keys.json` (then every tool checks that
the file holds that key). Merge `release-key` into `main` only **after** this commit: until then `minisign.pub` on the
branch is the placeholder, and the Release workflow, `make sign`, `scripts/mirror/install.sh` and
`scripts/deploy-builder-site.sh` refuse to work with it (that is the point).

## 4. The documents that name the key

- `SECURITY.md` (repository root), section "Release signing keys": replace `<KEY ID>` / `<PUBLIC KEY LINE>` with the
  new key's id and its second line.
- `docs/RELEASE.md`: the release-notes template's key line.

## 5. The builder page, before the next release

The page embeds the keys at build time, so the deployed page must be rebuilt **before** the first release signed
with the new key; otherwise the page in production refuses that release ("made with key ..., which this page does not
trust"). From the merged `main`:

```bash
make builder-emulator                    # build/builder/manifest.json: "release_key": "<KEY ID>"
make builder-test
scripts/deploy-builder-site.sh --dry-run
scripts/deploy-builder-site.sh --chown aldotech:aldotech
ssh build runuser -u aldotech -- /opt/aldotech-site/publish.sh
```

`deploy-builder-site.sh` refuses a page built with the placeholder. Check in a browser: the release list still shows
v0.4.1 and v0.4.0 with "signed with the project's former test key", and choosing them verifies.

## 6. The release mirror on the server, before the next release

The mirror on aldo.tech (systemd `urmqtt-mirror`, docs/DEPLOY.md section 10) today runs with
`--pubkey /etc/urmqtt-mirror/minisign.pub`, which holds the test key. Replace it by the key ring, from a checkout of
the merged `main` on the server, as root:

```bash
cd /path/to/urMQTT && git pull --ff-only
sudo scripts/mirror/install.sh --dry-run   # shows: minisign.pub replaced (a warning names both keys),
                                           #   keys/release-keys.json and the test key installed, the unit updated
sudo scripts/mirror/install.sh             # installs /etc/urmqtt-mirror/{minisign.pub,keys/}, the unit
                                           #   (ExecStart ... --keyring /etc/urmqtt-mirror/keys/release-keys.json),
                                           #   daemon-reload, enable --now the timer
sudo systemctl start urmqtt-mirror
journalctl -u urmqtt-mirror -n 30 --no-pager   # "mirroring ... (keys <NEW ID> (release, v0.4.2 and later),
                                               #   9229E05252D01F8E (test, v0.1.0 to v0.4.1); ...)", exit 0
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -A6 '"keys"'
```

Nothing is downloaded again: the releases already mirrored stay as they are; their `signed_by` in `releases.json` is
read from the signature files on disk (test key). If the install script stops with "minisign.pub is still the
placeholder", step 3 is not in the checkout.

## 7. The first release with the new key

Follow docs/RELEASE.md. The workflow now refuses to start without the key, waits for your approval of the `sign` job
(it fails there without the environment secret), publishes
`urmqtt-<tag>.elf/.iso/.img`, the template, the SBOM, `SHA256SUMS` and its signature, and checks that the signature
verifies with `minisign.pub`. Then, in an empty directory:

```bash
gh release download vX.Y.Z --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/vX.Y.Z/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub      # key id: the new one; comment "urMQTT vX.Y.Z release <commit>"
shasum -a 256 -c SHA256SUMS
```

And on the page: the new release verifies "(key <NEW ID>)" without the test-key note; v0.4.1 still verifies with the
note.

## Security notes

- **The test key is compromised from today.** Its secret sat passwordless in a CI secret and on a developer machine; it
  must be treated as known to others. It is kept only to verify v0.1.0 to v0.4.1, and every tool limits it to those
  tags. A file signed with it that claims a later tag is a forgery (docs/VULNERABILITY-HANDLING.md).
- **The old releases are pinned.** The range alone would let someone with the test secret sign a *different*
  `SHA256SUMS` and label it with an old tag (say v0.4.1). The key ring therefore pins the SHA-256 of the published
  `SHA256SUMS` of each of the six test-key releases (v0.1.0 to v0.4.1), and the page, the mirror and
  `urmqtt-config check-release --keyring` accept nothing else for those tags; a tag that is not pinned cannot use the
  test key. Pinning covers `SHA256SUMS` and every file it lists, nothing beyond (an asset added to an old release later
  is under no signature); and the pins are as trustworthy as the repository: a compromised GitHub account could change
  them only through a commit to `keys/release-keys.json`, which shows in the history and reaches the page and the
  mirror only when they are rebuilt or reinstalled. Check it before steps 5 and 6: `git log -p keys/release-keys.json`.
- **Where the key is used.** Only in the Release workflow's `sign` job (environment `release`, your approval): it
  checks out `minisign.pub` alone, takes `SHA256SUMS` from the `build` job, signs it with the key on a pipe (never a
  file) and runs no build code. The `build` job, which runs third-party code (build scripts, proc macros, apt
  packages), holds no secret and no write permission; the `publish` job (attestations, the GitHub release) builds
  nothing. `scripts/check-release-workflow.py` (CI) refuses a workflow that moves the key back next to the build
  (ADR-380). Before you approve the `sign` job, look at the `build` job's log: the tag, its commit on `main`.
- If the **new** secret leaks: generate another key, add it to `keys/release-keys.json` with `valid_from` the next tag,
  give the leaked key a `valid_to` of the last tag it signed, and repeat steps 2 to 6. Say so in an advisory.

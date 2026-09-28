
Okay that sounds reasonable... i guess i could also make an agent-sudo binary that basically provides this... have it use the standard sudo configuration files, but also secondary agent sudo config for anything special i want ot be able to configure...  allow some extra cli option for passing some textual context for the request to display and maybe add a skill for using it to get the coding agents to add the extra context (this part optional) or choose to just alias it / replace the binary / install the binary in an earlier PATH so i don't poison shits.

Worked for 15s
Yes — that’s probably a cleaner product boundary.

I’d make agent-sudo a separate executable with its own small privileged daemon, while reusing sudoers as the baseline authorization policy and layering your agent-specific rules on top.

The key distinction is:

sudo
  = normal human sudo behavior

agent-sudo
  = sudoers policy
    + agent approval workflow
    + remote grants
    + optional request context
That avoids patching distro sudo, and it also avoids surprising random shell scripts.

I would not start by literally replacing /usr/bin/sudo. Put agent-sudo earlier in the agent environment only, or teach the agents to call it. That keeps normal system behavior intact.

The flow I'd want is:

agent-sudo [options] command args...
        |
        | unprivileged client
        v
 /run/agent-sudo.sock
        |
        v
 agent-sudod   (root)
        |
        +-- evaluate standard sudoers policy
        |
        +-- evaluate /etc/agent-sudo.conf
        |
        +-- existing scoped grant?
        |       |
        |       +--> yes -> execute
        |
        +-- approval service
                |
             approve
                |
             execute
One caution: don't write a second half-correct sudoers parser.

Sudo's policy semantics are surprisingly deep: aliases, command arguments, digests, run-as users/groups, hosts, tags, defaults, environment handling, sudoedit, etc. The current sudo code still implements sudoers as its default policy plugin, and only one policy plugin can be active in a sudo process. 

So I'd reuse the upstream sudoers implementation in one of two ways:

Link/use the relevant sudoers code internally in your privileged daemon, if you are comfortable tracking upstream internals.
Better initially: have the root daemon invoke/query the installed sudo machinery for the policy decision, and keep your own policy limited to additional restrictions or grants, rather than replacing sudoers semantics.
I'd strongly favor:

standard sudoers says NO
    -> agent-sudo NO

standard sudoers says YES
    -> agent-sudo policy decides:
         existing agent grant?
         remote approval?
         extra restriction?
rather than letting /etc/agent-sudo.conf expand what sudoers permits by default.

You could add an explicit escape hatch later:

AllowBeyondSudoers = false   # default
but I'd make that opt-in and visually obvious.

Your context idea is good
Something like:

agent-sudo \
  --context "Installing kernel headers needed to build the NVIDIA RDMA module" \
  apt install linux-headers-$(uname -r)
Then your request shows:

moa
agent: codex / ds41rt worker 3
cwd: /home/tj/Developer/ds41rt

Reason:
Installing kernel headers needed to build the NVIDIA RDMA module

Command:
/usr/bin/apt install linux-headers-6.17.0-1032-nvidia
I'd probably support both:

--context TEXT
--context-file FILE
and possibly structured metadata:

agent-sudo \
  --context "Restarting NCCL service after config change" \
  --tag project=ds41rt \
  --tag task=rdma-debug \
  systemctl restart ...
But importantly: context is display-only and never security-sensitive.

An agent can lie.

The authorization decision should be based on things the privileged daemon can independently establish:

uid
gid
host
actual executable
argv
cwd
target uid/gid
session identity
agent identity
tty / no tty
A skill is probably enough to make agents use it properly
I'd give them a tiny instruction:

When privilege escalation is required, use agent-sudo instead of sudo.

Include --context with a short human-readable explanation of why the
privileged action is necessary and what you expect it to change.

Do not split one logical privileged operation into multiple requests
unless necessary.
Then agents naturally produce:

agent-sudo \
  --context "Reloading systemd after installing the new service unit" \
  systemctl daemon-reload
rather than:

sudo systemctl daemon-reload
You could even make the client infer useful metadata so agents don't have to provide most of it:

git repo
git branch
parent process
agent executable
PTY
SSH session
cwd
and reserve --context for the human explanation.

PATH interception is attractive, but I'd do it carefully
For the agent environment:

export PATH="$HOME/.agent-tools:$PATH"
with:

~/.agent-tools/sudo -> /usr/local/bin/agent-sudo
is actually reasonable.

Then existing coding agents that blindly type:

sudo apt install ...
get your system automatically.

The nice thing is that it only affects the agent's environment.

I'd avoid globally doing:

/usr/local/bin/sudo
ahead of /usr/bin for every shell until you're very confident in compatibility.

A shim could also support an escape hatch:

sudo --real-sudo ...
or:

/usr/bin/sudo ...
for cases where you explicitly want normal behavior.

Make CLI compatibility a goal, but not perfect compatibility
I would support the common subset:

-u USER
-g GROUP
-E
-H
-i
-s
--preserve-env
--
plus yours:

--context
--context-file
--approval-scope
--approval-timeout
--agent-session
But I wouldn't attempt to clone every obscure sudo CLI feature initially.

For anything unknown:

agent-sudo: unsupported sudo option: -XYZ
Use /usr/bin/sudo if this behavior is required.
Better than silently getting semantics wrong.

One especially nice behavior
Your agent-specific config could define default approval classes:

class package-manager {
    command = /usr/bin/apt
    hosts = sparks
    default_scope = session
    max_ttl = 30m
}

class systemctl-safe {
    command = /usr/bin/systemctl
    argv_prefix = ["restart", "nvidia-"]
    default_scope = exact-command
    max_ttl = 1h
}

class root-shell {
    command = ["/bin/bash", "/bin/sh"]
    require_each_time = true
    remote_only = true
}
Then the UI can offer sensible scopes instead of forcing you to manually construct policies every time.

And because you're separating it from sudo, you can do things sudo really wasn't designed around, like:

Approve:
[x] exact command
[x] this session
[x] moa + ostrich + emu
[x] next 45 minutes

Context:
"Running the same NVIDIA driver repair on the affected Sparks"
That's likely much nicer than trying to bend PAM/sudo plugins until they behave like an agent authorization system.

The only hard part I'd treat as security-critical engineering is the privileged execution boundary: the root daemon should receive a structured executable + argv, resolve/check it itself, never execute a shell string, and never trust policy-relevant metadata supplied by the unprivileged client.

I guess policy wise i'd want to centralize that in the service component, which doesn't run on the host, so really the primary config is pointing to the service that grants approvals... so wouldn't i just fork sudo to get it perfectly impemented and add the pre-auth parallel path?

Worked for 36s
Yes. Given what you actually want, I think a small sudo fork is cleaner than building a parallel agent-sudo implementation.

More specifically, I’d try hard not to fork the whole behavior of sudo. I’d carry a small patch against upstream sudo/sudoers so everything difficult remains upstream’s implementation: sudoers parsing, Runas, command matching, environment filtering, sudoedit, timestamps, PAM, logging, PTYs, signals, -u, -g, etc. The sudoers plugin is already the component that determines privileges and handles normal user authentication/timestamp behavior. 

The local config could then be almost trivial:

ApprovalService https://sudo.example.internal
ApprovalCA /etc/agent-sudo/ca.pem
HostIdentity /etc/agent-sudo/host.pem
ConnectTimeout 2s
RequestTimeout 10m
FailureMode deny
Everything interesting lives centrally:

user
host / host groups
command + argv
target uid/gid
cwd
interactive / headless
agent session
request context
previous grants
time limits
matching scope
approval history
The patched sudo flow
I’d make the behavior approximately:

sudo foo
   |
   v
normal sudoers parsing / resolution
   |
   +-- sudoers says NO ----------> normal sudo denial
   |
   +-- NOPASSWD -----------------> execute normally
   |
   +-- valid standard timestamp -> execute normally
   |
   `-- authentication required
             |
             +-----------------------------+
             |                             |
             v                             v
       normal PAM/password           central service
       if interactive              send full request
             |                             |
             |                      cached grant?
             |                      auto policy?
             |                      human approval?
             |                             |
             +----------- first SUCCESS ---+
                             |
                             v
                          execute
That preserves exactly the intuition you had:

If ordinary sudo already wouldn't ask me anything, don't bother me with the service.

Otherwise, you get the race.

And because you're inside sudoers rather than PAM, the remote request can contain the actual authoritative resolved command information, not an approximation reconstructed from /proc. That's the big win.

One subtle thing I would change from normal sudo semantics
A password success should update the normal sudo timestamp exactly as upstream sudo does.

A remote approval should probably not update the normal sudo timestamp by default.

Suppose you remotely approve:

systemctl restart nvidia-persistenced
for this agent session for 30 minutes.

If that remote approval wrote the ordinary sudo timestamp, the agent might immediately be able to run:

sudo rm ...
sudo apt ...
sudo bash
without talking to your service, simply because sudo now considers the user's authentication fresh.

Instead:

password succeeds
    -> ordinary sudo timestamp updated

remote succeeds
    -> central grant remains central
    -> don't create/refresh ordinary sudo timestamp
Then your central service retains the exact scope you chose.

You could offer an explicit approval option like:

○ approve this request
○ approve matching requests for 30 min
○ authenticate normal sudo session for 15 min
That last one would deliberately create/refresh the ordinary sudo timestamp.

There's an important distinction between "policy" and "approval"
I'd still leave sudoers as the local hard ceiling:

sudoers denies
    -> service never gets to override it
Then the central service decides whether a command that sudoers considers eligible may proceed without the normal password.

For your machines that might simply mean your ordinary sudoers is broad:

tj ALL=(ALL:ALL) ALL
and therefore nearly all of the interesting granular policy lives remotely.

That's safer operationally because if your NAS/service gets compromised, it still cannot give some unprivileged account powers that the local host's sudoers never granted.

If you later do want central policy to be authoritative enough to grant privileges absent from /etc/sudoers, that's possible too, but at that point you're replacing sudoers policy rather than augmenting authentication. I wouldn't start there.

I would make "deny" semantics configurable too
Your earlier model was "whichever finishes first approves it." That's subtly different from "whichever finishes first decides it."

I'd use:

password success       -> ALLOW
remote approval        -> ALLOW

bad password attempt   -> keep waiting
remote human denial    -> maybe keep password path alive
timeout                -> whichever paths remain determine failure
For normal personal use, a remote deny could simply close the remote path while still allowing you to type your password.

But for commands you've marked centrally as higher-risk, you might want:

remote denial -> hard DENY
regardless of whether somebody knows the Unix password.

That gives you policy classes later without redesigning the mechanism.

Interactive prompt behavior
You can make it feel indistinguishable from normal sudo:

$ sudo systemctl restart docker
[sudo] password for tj:
while the notification silently fires.

If you type your password:

$ sudo systemctl restart docker
[sudo] password for tj:
and it just runs.

If you approve on your phone while the cursor is sitting at the password prompt:

$ sudo systemctl restart docker
[sudo] password for tj:
Approved remotely.
and it runs.

For a headless agent:

$ sudo systemctl restart docker
Waiting for approval [01K...]
Approved.
No fake password prompt.

Optional agent context fits naturally
You can add one backward-compatible extension to your fork:

sudo --approval-context \
  "Restarting NVIDIA persistence daemon after changing GPU config" \
  systemctl restart nvidia-persistenced
or perhaps a less collision-prone namespace:

sudo --remote-context "..."
Your agent skill could teach agents to supply it, but ordinary software calling sudo remains completely normal.

I'd also accept context through an fd/environment mechanism for cases where you don't want to add CLI arguments, but treat it solely as untrusted descriptive text.

The central service request can show:

Host: moa
User: tj
Target: root
TTY: none
Agent session: ds41rt/codex-worker-3

Command:
/usr/bin/systemctl restart nvidia-persistenced.service

Agent explanation:
Restarting NVIDIA persistence daemon after changing GPU config
Maintaining the fork is probably not terrible
Sudo's source is ISC-licensed, explicitly permitting modification and redistribution, so carrying a private fork is straightforward legally. 

And if you keep your patch narrowly around the authentication boundary instead of changing parsers/execution machinery, I'd expect it to be a relatively small forward-port whenever you update sudo.

I would structure your source tree so almost all of your implementation lives separately:

plugins/sudoers/
    upstream stuff

plugins/remote_approval/
    client.c
    protocol.c
    request.c
    race.c
    config.c
with something close to a one-line conceptual hook in sudoers:

auth_result = remote_approval_authenticate_or_pam(ctx, ...);
rather than scattering custom logic throughout sudo.

So yes: for your requirements, I think a narrowly patched sudo/sudoers fork is actually the least weird solution. You get 100% sudo command compatibility, existing sudoers remains the safety boundary, and you add exactly one new authentication outcome: remotely approved. 

I think I also want an LLM call component that can be passed the context and make be able to fill out suggested defaults, and provide a risk score... it would receive recent context / approval information last N requests within a limited time, and used structured json and a standard chat/completions api call with a registered llm provider or a standard decisions api call openrouter.ai/api/alpha/decisions depending on how its configured (this is a cool alpha api https://openrouter.ai/docs/api/api-reference/alphadecisions/submit-a-decisions-request)


Worked for 21s
Yes — I think that makes the approval service substantially better. I’d make the LLM a first-class advisory component of the central service, with a provider abstraction so you can choose either an OpenAI-compatible structured-output model or OpenRouter’s Decisions API.

The service flow becomes:

sudo on host
    |
    | signed request
    v
central approval service
    |
    +--> deterministic policy / existing grants
    |
    +--> persist request
    |
    +--> send UI/push immediately
    |
    `--> LLM decision analysis
              |
              v
        risk + suggested defaults
              |
              v
         update live UI
Crucially, I would not wait for the LLM before notifying you. The request appears immediately and the analysis fills in milliseconds/seconds later. Password authentication on the machine is also racing all of this independently.

The input state
I'd give the judgment engine a deliberately structured object rather than a prose prompt:

{
  "request": {
    "host": "ostrich",
    "host_groups": ["spark", "cluster"],
    "user": "tj",
    "target_user": "root",
    "interactive": false,
    "cwd": "/home/tj/Developer/ds41rt",
    "executable": "/usr/bin/systemctl",
    "argv": [
      "systemctl",
      "restart",
      "nvidia-persistenced.service"
    ],
    "agent_context": "Restarting NVIDIA persistence after updating GPU configuration",
    "session_id": "codex-b29..."
  },

  "recent_history": [
    {
      "age_seconds": 214,
      "host": "emu",
      "command": [
        "/usr/bin/systemctl",
        "restart",
        "nvidia-persistenced.service"
      ],
      "decision": "approved",
      "scope": "once"
    },
    {
      "age_seconds": 480,
      "host": "ostrich",
      "command": [
        "/usr/bin/apt-get",
        "install",
        "nvidia-driver..."
      ],
      "decision": "approved",
      "scope": "session"
    }
  ],

  "current_grants": [...],

  "deterministic_features": {
    "writes_system_configuration": true,
    "starts_or_stops_service": true,
    "root_shell_capable": false,
    "matches_recent_approved_command": true
  }
}
I'd make history selection configurable along two dimensions:

history.max_requests = 20
history.max_age = 30m
and perhaps filters:

same_user       = true
same_session    = preferred
same_host_group = true
That lets the model recognize things like:

“TJ just approved this exact operation on five other Sparks.”

without giving it your whole audit history.

One normalized result schema
Regardless of backend, your service should consume one internal type:

{
  "risk": {
    "score": 23,
    "confidence": 0.94
  },

  "suggestion": {
    "decision": "approve",
    "scope": "exact_command",
    "hosts": "host_group",
    "ttl_seconds": 1800
  },

  "flags": {
    "destructive": false,
    "privilege_escape": false,
    "credential_access": false,
    "persistent_security_change": false,
    "unusual_relative_to_history": false
  },

  "summary": "Same service restart recently approved on peer Spark nodes."
}
Then neither your UI nor policy engine cares whether that came from GPT/GLM/Claude/etc. or Jev.

And the service validates every field. The model can suggest:

all_hosts / 24 hours
but if configuration says the maximum allowed suggestion is:

same_host / 30 minutes
the suggestion gets clipped before it ever reaches the UI.

The OpenRouter Decisions API is almost unusually well suited to this
The current alpha API takes a JSON state plus multiple typed questions in one request. It supports choice, ordered score, and noul probability questions, and the response includes probabilities/confidence rather than requiring you to parse generated prose. 

So your request could conceptually ask:

{
  "model": "typesafe/jev-1.13",
  "state": {
    "...": "the structured sudo request and history"
  },

  "questions": {
    "risk": {
      "type": "score",
      "instructions": "Assess the security and operational risk of allowing this privileged command.",
      "criteria": [
        "Routine, narrowly scoped, readily reversible",
        "Low-risk privileged system operation",
        "Moderate risk or meaningful system modification",
        "High-risk broad privilege or potentially destructive action",
        "Critical risk: unrestricted privilege, credential/security changes, or major destructive potential"
      ]
    },

    "scope": {
      "type": "choice",
      "instructions": "What is the broadest reasonable approval scope?",
      "criteria": {
        "once": "...",
        "exact_session": "...",
        "exact_command_10m": "...",
        "exact_command_30m": "...",
        "host_group_30m": "..."
      }
    },

    "privilege_escape": {
      "type": "noul",
      "instructions": "Could this command reasonably be used to obtain an unrestricted root execution path?"
    },

    "destructive": {
      "type": "noul",
      "instructions": "Could this operation cause substantial destructive or difficult-to-reverse changes?"
    }
  }
}

A Decisions score response isn't just an integer category: it returns the ordered legend, probabilities for the levels, a continuous score across them, and confidence. choice similarly gives the selected option plus probabilities for all alternatives. 

That is much nicer for your UI than pretending an ordinary LLM-generated "risk": 23 has calibrated mathematical significance.

For example:

Risk            LOW ━━━━━━━────────  24/100
Confidence                         96%

Likely scope
● Exact command / 30 min           72%
○ Once                             18%
○ Session                           8%
○ Host group                        2%
You can map the Decisions score onto 0–100 for display while retaining its raw probabilities internally.

I'd use more than one risk dimension
A single risk number hides useful information. I'd show the number prominently but have the model separately judge:

destructive potential
privilege expansion / shell escape
persistence
credential / secret exposure
network/security configuration
availability impact
unusualness relative to recent activity
similarity to previously approved activity
This makes a request such as:

systemctl restart nvidia-persistenced

look like:

Overall risk:       18
Destructive:         3%
Privilege escape:    1%
Persistence:         2%
Availability:       31%
Familiar operation: 96%
whereas:

bash

might look like:

Overall risk:       93
Privilege escape:   99%
Scope containment: effectively none
That gives you much more useful information than one magic score.

Ordinary LLM backend
For a conventional model, I'd require JSON Schema/structured output and use essentially the same state.

Configuration might be:

judgment:
  provider: openai-compatible

  endpoint: https://...
  api_key_env: SUDO_JUDGE_API_KEY
  model: glm-5.3-flash

  history:
    max_requests: 20
    max_age: 30m

versus:

judgment:
  provider: openrouter-decisions

  endpoint: https://openrouter.ai/api/alpha/decisions
  model: typesafe/jev-1.13

  history:
    max_requests: 20
    max_age: 30m

OpenRouter currently documents POST /api/alpha/decisions, with arbitrary JSON allowed as state and multiple questions evaluated in the same request. 

I'd probably call the abstraction something like:

DecisionAdvisor
rather than LLMProvider, because the Decisions backend isn't really a normal chat model.

Suggested defaults would be especially useful
Suppose an agent does:

sudo --remote-context \
  "Restarting the same daemon after deploying config to all Sparks" \
  systemctl restart nvidia-persistenced

and you've approved that exact command on four Sparks in the previous ten minutes.

The UI could automatically open as:

┌─────────────────────────────────────────────────┐
│ LOW RISK · 14/100                         97%   │
│                                                 │
│ systemctl restart nvidia-persistenced.service   │
│ moa · root                                     │
│                                                 │
│ Same operation approved on ostrich, emu,        │
│ kiwi and dodo in the last 9 minutes.            │
│                                                 │
│ Suggested grant                                 │
│                                                 │
│ ☑ Exact command                                 │
│ ☑ This Spark cluster                            │
│ ☑ Current agent session                         │
│                                                 │
│ Duration   [ 30 minutes ▼ ]                     │
│                                                 │
│      DENY                    APPROVE             │
└─────────────────────────────────────────────────┘
The LLM isn't granting anything. It's basically doing the tedious work of setting the checkboxes you'd probably choose.

And you can modify any of them before tapping approve.

I'd make history itself visible
This is important for trust.

Instead of merely:

AI says low risk.

show:

Why this suggestion?

• Exact executable was approved 4 times recently
• All previous requests were from this agent session
• Command is identical except host
• Target service is identical
• No shell interpreter or arbitrary command execution detected
For the normal LLM backend it can provide that explanation.

For Decisions/Jev, I wouldn't invent a textual chain-of-thought. I'd derive the UI explanation from the deterministic facts you supplied plus its returned classifications/probabilities.

The biggest security rule: model output isn't authorization
I'd make this architectural rather than merely a guideline:

                     +----------------+
request ------------>| deterministic  |
                     | policy engine  |
                     +-------+--------+
                             |
                      allowable envelope
                             |
                             v
                     +---------------+
                     | LLM advisor   |
                     +-------+-------+
                             |
                          suggestion
                             |
                             v
                     +---------------+
                     | policy clamp  |
                     +-------+-------+
                             |
                           UI
The advisor should have no API capable of issuing an approval token.

Later, if you decide you trust it enough to do low-risk automatic approvals, the deterministic policy engine can explicitly say something such as:

auto_approve:
  when:
    risk_max: 10
    confidence_min: 0.98
    destructive_max: 0.01
    privilege_escape_max: 0.01
    matches_recent_human_approval: true

  maximum_scope:
    hosts: same_host
    ttl: 10m

Then it's still your deterministic rule interpreting model outputs, not the model saying “I approve this.”

I wouldn't enable that initially, but designing for it now is easy.

One other thing I'd be strict about: what goes to the model
Do not send the complete environment to a hosted judge.

Commands frequently contain:

API keys
tokens
database passwords
signed URLs
Authorization headers
I'd have a server-side sanitizer before either LLM backend and tag fields by provenance:

{
  "agent_context": {
    "value": "...",
    "trusted": false
  },

  "resolved_executable": {
    "value": "/usr/bin/systemctl",
    "trusted": true
  }
}

The prompt should explicitly tell a normal LLM that agent context, argv, filenames, etc. are untrusted data, not instructions. That's also useful protection against an agent deliberately or accidentally putting prompt injection in --remote-context.

Overall, I think this turns the project from “remote sudo approval” into something much more interesting: a centralized privilege broker with human approval, scoped capabilities, historical context, and probabilistic decision assistance. And OpenRouter's new Decisions API is a particularly clean optional backend for the classification/scoring half because it already models the output as choices, scores, and probabilities instead of prose. 

I guess for the web component part (since its running on a different service) it would need a user/password/auth registry and visiting the page to do approval would need to have an expiring cookie kind of thing so you login once in while but not every time.
Exactly. I’d treat web-user authentication and sudo approval authorization as separate layers.

Your web service would have a small account/device registry:

User
 ├─ password hash
 ├─ registered passkeys
 ├─ roles/permissions
 └─ devices
      ├─ "TJ iPhone"
      ├─ "Desktop Chrome"
      └─ push subscription(s)
After login, issue an opaque server-side session token in a cookie:

Set-Cookie: session=<256-bit-random>;
            Secure;
            HttpOnly;
            SameSite=Strict;
            Path=/
I would not use a self-contained JWT for this. An opaque token whose hash maps to a database session is much nicer here because you can instantly revoke a lost phone/browser.

Something like:

web_session
  id
  user_id
  token_hash
  device_id
  created_at
  last_used_at
  authenticated_at
  expires_at
  revoked_at
  auth_strength
Then you can have comfortable settings like:

idle expiration:       7 days
absolute expiration:  30 days
or whatever you prefer. Every normal visit and notification click just works until the session becomes stale.

I'd strongly prefer passkeys over making the password important
For this particular application, passkeys/WebAuthn are almost perfect.

Initial device registration:

username/password
      +
register Face ID / Windows Hello passkey
Thereafter:

cookie valid
    -> open approval screen immediately

cookie expired
    -> Face ID / Windows Hello
    -> new cookie
So on the iPhone you'd tap:

🔐 moa requests sudo
and normally land directly here:

systemctl restart nvidia-persistenced

Risk: 14 / 100
Agent: ds41rt worker
Reason: restart after GPU configuration

[DENY]                 [APPROVE]
No authentication ceremony on each approval.

If your 30-day session has expired, that same tap causes Face ID once and then continues to the request.

I would distinguish session validity from "recent strong authentication"
This gives you a nice risk-sensitive option later.

For example, the browser cookie could remain valid for 30 days, but you record:

strong_auth_at = 2026-09-27T04:50...
Then central policy can say:

ordinary sudo approval:
    valid logged-in session

very dangerous operation:
    strong auth within last 1 hour

changing approval policy:
    strong auth within last 5 minutes

adding another approving user:
    strong auth now
So:

systemctl restart foo

can be one tap.

Whereas:

bash

might show:

HIGH RISK

This grants unrestricted root execution.

Confirm with Face ID
That's much better than asking for a password every time while still providing a meaningful step-up for unusually powerful actions.

You could also have the LLM risk output feed the UX, but I wouldn't let the LLM alone decide whether reauthentication is mandatory. Have deterministic rules like:

require_recent_auth:
  root_shell: 5m
  modifies_approval_system: 0m
  credential_access: 5m

The LLM can additionally recommend step-up authentication.

Push subscriptions belong to the logged-in device
When the PWA enables notifications:

TJ
 └─ Device #4
      type: iphone-pwa
      name: TJ iPhone
      session: abc...
      push_subscription:
          endpoint: ...
          p256dh: ...
          auth: ...
The push notification itself is not an authorization credential.

It just contains something akin to:

/request/01K8F...
The PWA opens that route, the browser sends its normal secure cookie, and the server determines whether that logged-in user can approve it.

That also makes multiple places easy:

pending request
      |
      +----> iPhone PWA push
      +----> desktop PWA push
      +----> already-open desktop WebSocket
      `----> another registered device
Whichever approves it first atomically changes:

PENDING -> APPROVED
All the others immediately update to:

Approved by TJ · iPhone
And of course the password race on the actual machine can perform exactly the same state transition.

I'd make every browser/device individually revocable
The account UI should show:

Your devices

TJ iPhone
  Passkey ✓
  Push ✓
  Last active: now
  [Revoke]

Desktop / Chrome
  Passkey ✓
  Push ✓
  Last active: 3 min ago
  [Revoke]

Old MacBook
  Last active: 41 days ago
  [Revoke]
Revocation deletes/inactivates both its server-side sessions and its push subscriptions.

That's important because a long-lived cookie for an application that can authorize root access to a cluster is considerably more valuable than an ordinary website login cookie.

And I'd keep approval actions CSRF-resistant
SameSite=Strict already helps tremendously, but an approval endpoint should still require an anti-CSRF token/request binding rather than allowing:

GET /approve?id=123
Never make opening a notification URL itself approve anything.

It should be more like:

POST /api/requests/01K.../decision
Cookie: session=...
X-CSRF-Token: ...

{
  "decision": "approve",
  "scope": {...}
}
with the request ID, current request generation/version, and scope checked atomically on the server.

That protects against stale UIs as well. If your desktop already approved request 812, your iPhone's stale approval POST gets:

409 Request already resolved
rather than issuing another grant.

So yes: account registry + long-lived revocable browser/device sessions + passkeys + optional risk-sensitive reauthentication is the web-side model I'd use. It gives you the "tap a notification and approve in one tap most of the time" experience without making a captured cookie effectively immortal root authorization.

Okay so agent-sudo it is, in a way where i could use the agent-tools paradigm to shoehorn it in to replace sudo (therefore avoiding required skill registry), but offering skill to leverage extra context.   love passkey.
Yep — that feels like the right shape.

agent-sudo can be drop-in enough that agents don't need to know it exists:

~/agent-tools/sudo -> /usr/local/bin/agent-sudo

So an agent just emits:

sudo systemctl restart docker

and gets your approval path automatically. No required skill, no prompt dependence, no agent cooperation needed.

Then the optional skill only improves UX by teaching the agent to add context:

sudo --agent-context \
  "Restarting Docker after changing daemon configuration" \
  systemctl restart docker

If it doesn't, you still have the authoritative command, cwd, host, target user, session metadata, history, etc. The context is just extra explanatory text.

I'd now consider these the core architectural decisions:

agent-sudo: narrow fork/patch of sudo/sudoers so CLI and policy semantics remain upstream-compatible.
PATH shim per agent environment: transparently replaces sudo without modifying the machine globally.
Local sudoers remains the hard privilege ceiling.
Central service owns approval policy, grant matching, history, audit, and UI.
Cold interactive auth races normal PAM/password against remote approval.
Headless agent requests wait on the remote path.
Remote approval doesn't refresh normal sudo timestamps unless explicitly requested.
PWA + Web Push for desktop/iPhone.
Passkeys/WebAuthn for login and optional step-up auth.
Long-lived, revocable server-side browser sessions, so you aren't Face-ID'ing every ordinary request.
LLM/Decisions advisor fills suggested scope/TTL/risk, but doesn't itself possess the authority to issue grants.
Optional agent skill solely to add better request context.
And I especially like the agent-tools interception because it means you can roll it out incrementally:

human shell:
    /usr/bin/sudo

Codex environment:
    ~/agent-tools/sudo -> agent-sudo

Claude environment:
    ~/agent-tools/sudo -> agent-sudo

swarm workers:
    same thing
Then once you've beaten on it enough, you can decide whether you ever even want it system-wide. You may find that agent-only interception is actually the ideal permanent deployment, because human sudo stays boring and standard while agents get the richer brokered system.





# Agent Red-Teamer — Automated AI Agent Security Scanner

An automated security testing tool that attacks AI agents with known
prompt-injection and agent-security techniques, then uses an LLM-as-judge to
score whether each attack succeeded. Built specifically to test **SmartDesk
AI** (my other project) — but the approach generalizes to any agent that
exposes a chat-style API.

## Why this project exists

Most student AI projects stop at "build a chatbot." As companies push AI
agents into production — Salesforce's Agentforce, customer support bots,
internal tools with real data access — a live, current concern is: **can
someone trick the agent into leaking data, ignoring its instructions, or
taking actions it shouldn't?** This project builds the tool that answers
that question automatically, instead of manually trying a few jailbreak
prompts by hand.

## What makes this different from a typical project
- Tests **my own deployed AI system**, not a toy example — a real target
  with real architecture
- Covers **three distinct attack surfaces**, not just "try mean prompts":
  1. **Direct prompt injection** — attacking the user-facing conversation
  2. **Indirect prompt injection** — planting hidden instructions inside
     *data* the agent trusts (a ticket subject line), testing whether
     attacker-controlled data can hijack the agent even when the attacker
     never talks to it directly
  3. **History/context injection** — testing whether a fabricated prior
     "assistant" message in conversation history can trick the agent into
     believing it already agreed to something
- Uses the OWASP Top 10 for LLM Applications taxonomy (prompt injection,
  sensitive information disclosure, excessive agency) — real, named
  vulnerability classes, not made-up categories
- Automatically scores results with an LLM-as-judge and produces a
  proper written security report (`SECURITY_REPORT.md`)

## How it works

```
attacks.py            -- 14 attack cases across 6 vulnerability categories
       │
       ▼
redteam.py
  ├── Direct attacks    → sent over HTTP to the LIVE deployed API
  ├── History attacks   → sent over HTTP with fabricated conversation history
  └── Indirect attacks  → run against a LOCAL copy of the agent, with a
                           poisoned ticket injected into memory only
                           (never written to real data or the live deployment
                           — this mirrors real red-teaming practice: never
                           test injection payloads against production data)
       │
       ▼
LLM-as-judge scores each result: vulnerable or safe, with reasoning
       │
       ▼
generate_report.py → SECURITY_REPORT.md (shareable written report)
```

## Setup

1. Copy `.env.example` to `.env` and fill in:
   - `TARGET_URL` — your deployed SmartDesk AI backend URL
   - `GROQ_API_KEY` — your free Groq key (same one from SmartDesk AI)
   - `SMARTDESK_PATH` — path to your local `smartdesk-ai` checkout (for
     indirect attacks only)
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. On Windows, load the `.env` values into your terminal session:
   ```
   set TARGET_URL=https://your-backend.onrender.com
   set GROQ_API_KEY=your_key_here
   set SMARTDESK_PATH=..\smartdesk-ai
   ```

## Running it

```
python redteam.py
```

This runs all 14 attacks and prints live results, then saves
`redteam_report.json`.

```
python generate_report.py
```

This turns the JSON into a readable `SECURITY_REPORT.md` — commit this to
your repo as a real artifact.

## What to say about this in an interview

- **"Why build this instead of just adding more features to SmartDesk AI?"**
  Because measuring whether an AI system is *safe*, not just whether it
  *works*, is a distinct and increasingly important skill — this project
  demonstrates thinking about AI systems adversarially, which is exactly
  what companies deploying agents into production need.
- **"What's indirect prompt injection, and why does it matter more than
  direct injection?"** Direct injection requires the attacker to talk to
  the agent themselves. Indirect injection means *any* data the agent reads
  — a ticket, a document, a webpage it summarizes — can carry a hidden
  attack, even from someone who never interacts with the agent at all. It's
  a bigger and less obvious attack surface, and it's specific to my own
  agent's actual architecture (ticket subjects get fed into an LLM prompt).
- **"Why test the conversation-memory feature specifically?"** Because
  adding conversation memory to SmartDesk AI created a new attack surface
  that didn't exist before — trusting fabricated history is a realistic risk
  the moment you add memory to any agent.
- **"How would you extend this?"** Add more attack categories (denial-of-
  service via prompt flooding, multi-turn escalation attacks), test against
  multiple target agents to compare resistance rates, and add automatic
  retries/statistical confidence since LLM judges aren't perfectly
  consistent run-to-run.

## Honest limitations
- The LLM-as-judge itself isn't perfectly reliable — it's an approximation
  of "did this succeed," and could disagree with a human reviewer on edge
  cases. This is a known, general limitation of LLM-as-judge evaluation,
  not specific to this tool.
- The attack suite (20 cases) is illustrative, not exhaustive — a real
  red-team engagement would use hundreds of variations and adversarial
  automation to generate new attacks, not a fixed list.

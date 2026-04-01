# prompt-guard

**prompt-guard** is a Python library and CLI that **analyzes** text before it is sent to AI tools (Cursor, Copilot, etc.). It **detects** sensitive patterns (PII, secrets, profanity, India/global/org rules), **masks** them with stable placeholders, assigns a **risk score** (0–100), and optionally **persists analytics** to SQLite and logs. It **does not block** prompts by itself—callers (IDE extensions, MCP, proxies) decide how to warn users or replace text.

---

## What it does

| Capability | Description |
|------------|-------------|
| **Detection** | Regex + word lists across domains: `global`, `india`, `auth`, `organization`, enterprise buckets (`client_data`, `financial_data`, …), `demographics`, `toxicity`. |
| **Masking** | Replaces hits with tokens like `[MASKED_EMAIL]`, `[MASKED_PAN]`, `[MASKED_API_KEY]`. |
| **Risk score** | Weighted 0–100 from category counts (secrets weigh more than contact info). |
| **Analytics** | SQLite `prompt_guard_analytics.db`: rolling **aggregates** + per-request **audit** rows. |
| **Logging** | Optional `prompt_guard.log` (rotating) with hash, risk, findings; can be disabled. |
| **MCP** | `prompt-guard-mcp` exposes tools for Cursor/Claude Desktop (`analyze_prompt`, `prompt_guard_stats`). |

### Analytics database (SQLite)

Open `prompt_guard_analytics.db` in any SQLite viewer (VS Code extensions, DB Browser). WAL mode may create companion files (`-wal`, `-shm`) while the DB is open.

**Table `aggregates`** — rolling counters keyed by `key` / `value`:

| key | Meaning |
|-----|--------|
| `total_prompts` | Number of `analyze_prompt` calls recorded |
| `total_sensitive_items` | Sum of detections across all prompts |
| `masked_token_count` | Total masked spans applied |
| `cat:<leaf>` | Per-category lifetime counts (e.g. `cat:email`) |

![Aggregates table example](docs/assets/analytics-aggregates.png)

**Table `request_log`** — one row per analyzed prompt:

| Column | Meaning |
|--------|--------|
| `prompt_hash` | SHA-256 hash of the original text (not raw prompt) |
| `risk_score` | integer 0–100 |
| `masked_spans` | Count of masked regions for that prompt |
| `findings_json` | JSON object of **category → count** for that prompt only (e.g. `{"email":1}`) |

![Request log example](docs/assets/request-log.png)

---

## Requirements

- **Python 3.10+**

---

## Install (local development)

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Install dev tools (optional):

```bash
pip install -e ".[dev]"
```

Install **MCP** support (for Cursor / Claude Desktop):

```bash
pip install -e ".[mcp]"
```

This project uses a **flat package layout** (`package-dir` maps the import name `prompt_guard` to the repo root). Use **`pip install -e .`** so `import prompt_guard` and the `prompt-guard` CLI resolve correctly.

---

## MCP (Model Context Protocol)

Expose prompt-guard as **tools** over **stdio** so Cursor (and other MCP clients) can call analysis from chat.

### Setup checklist

1. **Install the extra** (from the repo root, venv active):

   ```bash
   pip install -e ".[mcp]"
   ```

2. **Confirm the binary exists** (adjust path to your machine):

   ```bash
   ls -la .venv/bin/prompt-guard-mcp
   ```

3. **Add the server in Cursor** — Settings → **MCP** (or edit `~/.cursor/mcp.json` / project MCP config, depending on your Cursor version). Use an **absolute** path:

   ```json
   {
     "mcpServers": {
       "prompt-guard": {
         "command": "/ABSOLUTE/PATH/TO/prompt-guard/.venv/bin/prompt-guard-mcp",
         "env": {
           "PROMPT_GUARD_NO_LOG": "1",
           "PROMPT_GUARD_SQLITE": ":memory:"
         }
       }
     }
   }
   ```

4. **Restart Cursor** (or reload the window) after saving.

5. **Use the tool explicitly** in chat — MCP does not run on every message. Ask the model to call **`analyze_prompt`** with the text to scan, e.g.  
   *“Use the prompt-guard MCP tool `analyze_prompt` on: …”*

### Tools

| Tool | Purpose |
|------|--------|
| `analyze_prompt` | Argument: `prompt` (string). Returns JSON: `masked`, `findings`, `matches`, `risk_score`, `stats_snapshot`, etc. |
| `prompt_guard_stats` | No arguments. Returns JSON aggregate stats from the analytics tracker. |

### MCP environment variables

| Variable | Effect |
|----------|--------|
| `PROMPT_GUARD_NO_LOG` | Set to `1` to disable library logging to `prompt_guard.log` / noisy handlers. |
| `PROMPT_GUARD_SQLITE` | SQLite path for analytics (e.g. `:memory:`). If `NO_LOG` is set and SQLite is unset, the code defaults to `:memory:` for the MCP helper. |

### Run the server manually (debug)

```bash
prompt-guard-mcp
```

The process speaks MCP over **stdin/stdout**; leave it running only when your MCP client launches it.

### Conceptual “request / response” (MCP)

- **Request:** The client invokes tool **`analyze_prompt`** with one string argument, `prompt` (the full user text to analyze).
- **Response:** A **JSON string** (the tool return value) with the same shape as the Python API below (`original`, `masked`, `findings`, `findings_flat`, `matches`, `risk_score`, `stats_snapshot`).

**Note:** MCP exposes **tools** the model can call; it does not scan every keystroke. Editor popups still require a separate extension or client UI.

---

## CLI

```bash
prompt-guard "My email is user@example.com"
```

Useful options:

| Flag | Meaning |
|------|--------|
| `--no-log` | Avoid writing `prompt_guard.log` and reduce logging noise |
| `--sqlite :memory:` | Keep analytics in memory only (no `prompt_guard_analytics.db` file) |
| `--compact` | Single-line JSON output |
| `--debug` | Verbose logging |

Read from stdin:

```bash
echo "some prompt text" | prompt-guard --no-log
```

---

## Python API

```python
from prompt_guard import analyze_prompt

result = analyze_prompt("Contact user@example.com and key sk-1234567890123456789012345678")
print(result["masked"])
print(result["findings"])       # nested by domain (e.g. global, india, auth)
print(result["findings_flat"])  # leaf key -> list of matches
print(result["matches"])        # value, type, domain, confidence, start, end
print(result["risk_score"], result["stats_snapshot"])
```

Configuration:

```python
from prompt_guard import analyze_prompt
from prompt_guard.config import PromptGuardConfig, RegexRuleSpec

cfg = PromptGuardConfig(
    custom_flagged_keywords=["acme-internal"],
    extra_profanity_words=["sucks"],
    custom_regex_rules=[RegexRuleSpec(name="ticket", pattern=r"\b[A-Z]+-\d{4,}\b")],
    sqlite_path=":memory:",
    logging_enabled=True,
)
analyze_prompt("...", config=cfg)
```

---

## Scenario audit script (DB-shaped output)

`tests/test_prompt_scenarios.py` runs **10 canned prompts** through `analyze_prompt`, writes a **temporary SQLite file**, and prints:

- **`aggregates`** — same columns as `prompt_guard_analytics.db` (`key`, `value`)
- **`request_log`** — `id`, `prompt_hash`, `risk_score`, `masked_spans`, `findings_json`

It also asserts each scenario’s **`risk_score`** and that `findings_json` is a JSON object of **category → count**.

```bash
# From repo root
pip install -e .
PYTHONPATH=. python tests/test_prompt_scenarios.py
```

With pytest:

```bash
pip install -e ".[dev]"
pytest tests/test_prompt_scenarios.py -v
```

---

## Real-world test scenarios (10)

All **`risk_score`** values below were produced with `PromptGuardConfig(logging_enabled=False, sqlite_path=":memory:")` (same engine as a quiet MCP run). Your scores can change slightly if rules or weights change.

| # | Scenario | Example input (short) | risk_score | What was detected (summary) |
|---|----------|------------------------|------------|-----------------------------|
| 1 | Clean code request | `Refactor the login handler to use async/await and add unit tests.` | **0** | None |
| 2 | Work email | `Contact me at jane.doe@company.com for the API review.` | **4** | `email` |
| 3 | US phone + email | `Reach me at +1 (415) 555-0199 or sarah@acme.io.` | **8** | `phone`, `email` |
| 4 | India PAN + IFSC | `PAN ABCDE1234F bank IFSC HDFC0001234 for the refund.` | **16** | `pan`, `ifsc` |
| 5 | API key (`sk-…`) | `Use this key in dev only: sk-1234567890123456789012345678` | **10** | `api_key_generic` |
| 6 | JWT bearer | `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XggTsoPtgdQ0Qf_obqQ3k` | **10** | `jwt_token` |
| 7 | Profanity | `This bug is shit and blocking the release.` | **2** | `profanity` |
| 8 | Enterprise-style leak | `CLIENT-9001 TXN-123456789 password: SuperSecret99 merger acquisition CASE-42` | **53** | `client_id`, `transaction_id`, `internal_password`, `mna_keywords`, `case_id` |
| 9 | Card + amount | `Charge 4242424242424242 exp 12/28 for the invoice USD 1,250.00` | **18** | `credit_card` (Luhn-valid), `amounts` |
| 10 | Mixed secrets | `Email a@b.com Aadhaar 2345 2345 2342 sk-1234567890123456789012345678` | **23** | `email`, `aadhaar`, `api_key_generic` |

**Caveats**

- **`sk-proj-…` and other vendor-specific prefixes** may not match `api_key_generic` until the regex includes them; use a `sk-` + length pattern that matches your rule set, or add a custom `RegexRuleSpec`.
- **PAN “validity”** is pattern + optional checks; **not** government verification.

---

## Sample request & response (Python API)

**Request (conceptual):** one string — the prompt to analyze.

```python
from prompt_guard import analyze_prompt
from prompt_guard.config import PromptGuardConfig

msg = "PAN ABCDE1234F bank IFSC HDFC0001234 for the refund."
result = analyze_prompt(msg, config=PromptGuardConfig(logging_enabled=False, sqlite_path=":memory:"))
```

**Response (JSON-like shape, abbreviated):**

```json
{
  "original": "PAN ABCDE1234F bank IFSC HDFC0001234 for the refund.",
  "masked": "PAN [MASKED_PAN] bank IFSC [MASKED_IFSC] for the refund.",
  "findings": {
    "india": {
      "pan": ["ABCDE1234F"],
      "ifsc": ["HDFC0001234"]
    }
  },
  "findings_flat": {
    "pan": ["ABCDE1234F"],
    "ifsc": ["HDFC0001234"]
  },
  "matches": [
    {
      "value": "ABCDE1234F",
      "type": "pan",
      "domain": "india",
      "confidence": 0.92,
      "start": 4,
      "end": 14
    }
  ],
  "risk_score": 16,
  "stats_snapshot": {
    "total_prompts": 1,
    "total_sensitive_items": 2,
    "masked_token_count": 2,
    "counts_by_category": { "pan": 1, "ifsc": 1 },
    "last_updated": "2026-04-01T12:00:00+00:00"
  }
}
```

`stats_snapshot.last_updated` and aggregate counts depend on how many calls you made in-process and whether analytics are enabled.

---

## Logging (usage logs)

When **`logging_enabled=True`** (default), the service configures the `prompt_guard` logger to:

- **Console (stderr):** human-readable lines.
- **File:** `prompt_guard.log` in the **current working directory** (rotating, size-limited).

Typical line format:

```text
2026-04-01 12:00:00 | INFO     | prompt_guard.service | analyze_prompt | hash=... | risk=16 | findings_nested={"india": {"pan": ["ABCDE1234F"], "ifsc": ["HDFC0001234"]}}
2026-04-01 12:00:00 | INFO     | prompt_guard.service | original_prompt=PAN ABCDE1234F bank IFSC HDFC0001234 for the refund.
2026-04-01 12:00:00 | INFO     | prompt_guard.service | masked_prompt=PAN [MASKED_PAN] bank IFSC [MASKED_IFSC] for the refund.
```

Use **`PromptGuardConfig(logging_enabled=False)`**, **`--no-log`** (CLI), or **`PROMPT_GUARD_NO_LOG=1`** (MCP) to avoid writing **full** prompts to disk when you do not want that.

---

## Artifacts (default)

With default settings, the library may create in the **current working directory**:

- `prompt_guard.log` — rotating log file
- `prompt_guard_analytics.db` — SQLite analytics (override with `PromptGuardConfig.sqlite_path` or CLI `--sqlite`)

---
## Project layout

| Path | Role |
|------|------|
| `config/` | Rules, `SENSITIVE_DATA_MAP`, masks, risk weights |
| `detector/` | Regex + profanity detection |
| `masker/` | Placeholder replacement |
| `analytics/` | SQLite tracker, `get_stats()` |
| `logger/` | Logging setup |
| `api/` | `analyze_prompt` service |
| `cli.py` | `prompt-guard` entry point |
| `prompt_guard_mcp.py` | MCP server (`prompt-guard-mcp`) |
| `tests/test_prompt_scenarios.py` | Scenario audit + unittest |
| `docs/assets/` | README screenshots |

## License

MIT (see `pyproject.toml`).

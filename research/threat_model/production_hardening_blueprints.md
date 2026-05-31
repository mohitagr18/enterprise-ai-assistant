# Sentinel AI — Production Hardening Blueprints

This document outlines architectural blueprints to address the security limitations identified in Sentinel AI's core evaluation. These blueprints describe how to implement production-grade security controls for model provenance, input obfuscation, log integrity, and agentic loop runaways without affecting the current system's baseline structure.

---

## 1. Input Normalization & Anti-Obfuscation (Pre-Layer 1)

### The Threat
Attackers bypass string-matching filters (Layer 1 regex) and confuse semantic classification models (Layer 2) using unicode homoglyphs, non-printable characters (e.g., zero-width spaces), or encoding envelopes (e.g., Base64, Hex).

### The Mitigation Architecture
Implement a pre-pipeline **Input Normalizer** that cleans, normalizes, and recursively decodes user payloads before they reach Layer 1.

```
[ Raw User Prompt ] 
       │
       ▼
┌──────────────────────────────────────────────┐
│  Unicode Normalization (NFKC)                │
│  - Maps homoglyphs to standard ASCII         │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Non-Printable Character Strip               │
│  - Removes zero-width spaces, null bytes     │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Recursive Envelope Decoder                  │
│  - Detects and decodes Base64, Hex, URL enc. │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
[ Clean, Normalized Prompt ] ──► [ Layer 1 Regex Filters ]
```

### Reference Implementation Blueprint
```python
import unicodedata
import re
import base64
import binascii

def normalize_input(text: str) -> str:
    # 1. Unicode Normalization (NFKC compatibility decomposition)
    # Resolves homoglyph spoofing (e.g., Cyrillic 'а' to Latin 'a')
    normalized = unicodedata.normalize('NFKC', text)
    
    # 2. Strip non-printable characters and control characters
    # Prevents zero-width space evasion
    normalized = "".join(ch for ch in normalized if unicodedata.category(ch)[0] != "C" or ch in "\n\r\t")
    
    # 3. Recursive Base64/Hex decoding
    # Prevents payload wrapping in encoding envelopes
    return decode_envelopes(normalized)

def decode_envelopes(text: str, max_depth: int = 3) -> str:
    if max_depth <= 0:
        return text
        
    # Check if the string matches a Base64 pattern
    base64_regex = r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_regex, text)
    
    decoded_text = text
    for match in matches:
        if len(match) < 16:  # Skip short strings to avoid false positives
            continue
        try:
            decoded_bytes = base64.b64decode(match, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            # Replace the encoded portion with the decoded string
            decoded_text = decoded_text.replace(match, decoded_str)
        except (binascii.Error, ValueError):
            pass  # Not valid base64
            
    # If the text changed, recursively decode (up to max_depth)
    if decoded_text != text:
        return decode_envelopes(decoded_text, max_depth - 1)
        
    return decoded_text
```

---

## 2. Model Provenance & Local ONNX Isolation (Layer 2)

### The Threat
Lazy-loading classification models from external repositories (like Hugging Face Hub) introduces risks of model hijacking, man-in-the-middle poisoning, or runtime code execution (RCE) via vulnerabilities in parsing libraries (e.g., PyTorch `pickle` deserialization or ONNX Runtime buffer overflows).

### The Mitigation Architecture
Convert the gateway into a fully air-gapped system by bundling verified model weights locally and running model inference inside a sandboxed sidecar.

```
                  ┌───────────────────────────────┐
                  │      Sentinel AI Gateway      │
                  └──────────────┬────────────────┘
                                 │
                   gRPC / IPC    │ (Normalized Prompt)
                   (Unix Socket) │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Inference Sandbox Sidecar                    │
│  - No internet access                                           │
│  - Low OS privilege (nobody / read-only filesystem)             │
│                                                                 │
│  ┌─────────────────────────┐       ┌─────────────────────────┐  │
│  │ Verified Local Models   │──────►│ ONNX Runtime            │  │
│  │ (SHA-256 Verified)      │       │ (C++ API, CPU Execution)│  │
│  └─────────────────────────┘       └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Engineering Practices
1.  **AOT (Ahead-of-Time) Weight Verification:** Build docker images containing the model weights. The startup script must assert weight signatures:
    ```bash
    echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /app/models/injection_detector.onnx" | sha256sum --check
    ```
2.  **Inference Isolation:** Run the ONNX Runtime library in a separate Unix process or container sidecar. The main web application communicates with the sidecar over a local gRPC or IPC channel, ensuring that an ONNX execution panic or memory leak does not crash the FastAPI application server.

---

## 3. Cryptographic Audit Chain & SIEM Streaming (Layer 9)

### The Threat
Local audit logs ([audit.jsonl](../../logs/test_audit.jsonl)) are vulnerable to tampering, deletion, or modifications by attackers who gain write access to the host server container, leaving no trace for forensic investigations.

### The Mitigation Architecture
Protect the audit trail by establishing a cryptographic hash chain for all log entries, and streaming them immediately to an external, write-once-read-many (WORM) security information and event management (SIEM) target.

```
┌───────────────────────────────────────┐
│          New Audit Log Entry          │
├───────────────────────────────────────┤
│  User ID, Timestamp, Layers Fired...   │
│  Previous Hash: SHA256(Entry N-1)     │
└──────────────────┬────────────────────┘
                   │
                   ▼
┌───────────────────────────────────────┐
│       Log Cryptographic Chaining      │
│  - Current Entry Hash calculated      │
└──────────────────┬────────────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
┌─────────────────┐ ┌─────────────────┐
│ Local App-Chain │ │ Secure TLS      │
│ (audit.jsonl)   │ │ gRPC/Syslog     │
└─────────────────┘ └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ External SIEM   │
                    │ (Splunk/Datadog)│
                    └─────────────────┘
```

### Reference Implementation Blueprint
```python
import hashlib
import json
import time

class SecureAuditChain:
    def __init__(self, log_filepath: str):
        self.log_filepath = log_filepath
        self.last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        try:
            with open(self.log_filepath, "r") as f:
                # Read the last line to get the previous entry's hash
                lines = f.readlines()
                if not lines:
                    return "0" * 64
                last_entry = json.loads(lines[-1].strip())
                return last_entry.get("entry_hash", "0" * 64)
        except FileNotFoundError:
            return "0" * 64

    def log_event(self, event_data: dict):
        event_record = event_data.copy()
        event_record["timestamp"] = time.time()
        event_record["previous_hash"] = self.last_hash
        
        # Calculate current entry hash
        serialized = json.dumps(event_record, sort_keys=True)
        current_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        event_record["entry_hash"] = current_hash
        
        # Write locally
        with open(self.log_filepath, "a") as f:
            f.write(json.dumps(event_record) + "\n")
            
        # Update state
        self.last_hash = current_hash
        
        # Push to external log service asynchronously
        self._stream_to_external_siem(event_record)

    def _stream_to_external_siem(self, record: dict):
        # Async stream over mutual-TLS to a Splunk, Datadog, or centralized Syslog collector
        pass
```

---

## 4. Recursion Limits in Agentic Loops (Layer 5/10)

### The Threat
While daily token quotas prevent slow-moving cost abuse, a multi-step agent (which generates planning steps and invokes tools dynamically) can enter an infinite loop during a single chat request. This can exhaust the entire daily token budget and generate hundreds of dollars of API costs in a matter of seconds.

### The Mitigation Architecture
Implement execution-depth controls within the LLM agent client orchestration code to short-circuit runaway execution before budget thresholds are hit.

```
       [ User Request ]
              │
              ▼
┌──────────────────────────────┐
│  Initialize Request Loop     │
│  - Set Depth Count = 0       │
└─────────────┬────────────────┘
              │
              ▼
    ┌──────────────────┐
    │ Depth >= Max?    ├──────► [ Yes ] ──► Block Request (Lockout)
    └─────────┬────────┘
              │ [ No ]
              ▼
┌──────────────────────────────┐
│  Invoke LLM Tool Planner     │
└─────────────┬────────────────┘
              │
              ▼
    ┌──────────────────┐
    │  Tool Called?    ├──────► [ No ] ──► Return final response
    └─────────┬────────┘
              │ [ Yes ]
              ▼
┌──────────────────────────────┐
│  Execute Tool                │
│  Increment Depth Count       │
└─────────────┬────────────────┘
              │
              └──────────────── (Loop Back)
```

### Reference Implementation Blueprint
```python
class SafeAgentOrchestrator:
    def __init__(self, llm_client, max_depth: int = 5):
        self.llm_client = llm_client
        self.max_depth = max_depth

    async def execute_agent_loop(self, user_prompt: str, user_id: str) -> str:
        depth = 0
        messages = [{"role": "user", "content": user_prompt}]
        
        while depth < self.max_depth:
            # Generate next step from LLM
            response_text = await self.llm_client.create_chat_completion(messages)
            
            # Parse if the LLM plans a tool invocation (e.g. JSON-formatted tool calls)
            tool_call = self._parse_tool_call(response_text)
            if not tool_call:
                return response_text  # Final answer achieved
                
            # Execute tool and append the result to conversation history
            tool_result = await self._execute_tool(tool_call)
            messages.append({"role": "assistant", "content": response_text})
            messages.append({"role": "tool", "content": tool_result})
            
            depth += 1
            
        # Limit breached - short-circuit the loop to prevent token consumption runaways
        raise RuntimeError(
            f"Agentic loop halted: Maximum recursion depth ({self.max_depth}) exceeded. "
            "Execution interrupted to prevent runaway budget consumption."
        )
        
    def _parse_tool_call(self, text: str) -> dict | None:
        # Tool call parsing logic
        pass

    async def _execute_tool(self, tool_call: dict) -> str:
        # Tool execution logic
        pass
```

---

## 5. Multi-Provider API Failover (Resilience Architecture)

### The Threat
A fail-closed gateway will completely block all enterprise user traffic if the upstream provider (e.g., OpenAI) goes down or encounters rate-limiting errors (HTTP 429), creating a denial-of-service state.

### The Mitigation Architecture
Incorporate a provider-agnostic LLM interface layer that dynamically falls back to an alternative hosted endpoint (e.g., Anthropic Claude or a locally hosted Llama instance) while preserving all token formatting and safety structures.

```python
class ResilienceLLMClient:
    def __init__(self, primary_client, fallback_client):
        self.primary = primary_client
        self.fallback = fallback_client

    async def chat_with_retry(self, messages: list[dict], user_id: str) -> str:
        try:
            # Try primary OpenAI model
            return await self.primary.create_chat_completion(messages)
        except Exception as primary_error:
            # Log primary failure
            print(f"Primary provider failed: {str(primary_error)}. Initiating failover...")
            
            # Switch provider dynamically
            return await self.fallback.create_chat_completion(messages)
```

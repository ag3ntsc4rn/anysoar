# anysoar

Vendor-agnostic adapter that lets AI agents operate any SOAR platform through one interface.

> **Status: pre-alpha.** This release only reserves the package name and contains no usable
> functionality yet. Follow progress at <https://github.com/ag3ntsc4rn/anysoar>.

Agents talk to anysoar; anysoar translates to whichever SOAR sits underneath through a
per-vendor driver. Swapping vendors means swapping a driver, not rewriting agents.

```bash
pip install anysoar            # core
pip install "anysoar[mcp]"     # MCP server (planned)
pip install "anysoar[shuffle]" # Shuffle driver (planned)
```

Licensed under Apache 2.0.

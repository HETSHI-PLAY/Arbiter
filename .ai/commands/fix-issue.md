# /fix-issue — Root-cause a reported bug

Do not patch symptoms. Follow the systematic-debugging loop:

1. **Reproduce** — express the failure as a test or a curl against the running
   app (never against production data).
2. **Read the real error** — don't mask upstream bodies; log the actual
   response so a 400 from Wazuh Indexer says *why* it was rejected.
3. **Fix the root**, not the message.
4. **Add a regression test** (synthetic fixture).
5. **Verify** — `npm test` + safe backend suites.

Report: root cause, the minimal change, and the verification that ran.

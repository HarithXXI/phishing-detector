# Local E2E Test Report

**Date:** 2026-07-20  
**Tester:** Autonomous QA Engineer  
**App:** PhishGuard AI - Phishing Detection Web App  

---

## Startup & Infrastructure Status

| Check | Expected | Result | Status |
|-------|----------|--------|--------|
| Backend on port 8000 | Application startup complete | Active on port 8000 | `[PASS]` |
| Frontend on port 5500 | Serving HTTP | Active on port 5500 | `[PASS]` |

## UI & Design Verification

| Check | Expected | Result | Status |
|-------|----------|--------|--------|
| Page Load | http://localhost:5500 loads cleanly | Loaded successfully | `[PASS]` |
| Design Aesthetics | Human & Professional (White/Gray/Black/Blue only, no pink/purple gradients) | CSS verified & visual check passed (#2563EB accent, #FFFFFF bg) | `[PASS]` |
| Component Presence | Textarea + Analyze button present | Present and interactive | `[PASS]` |
| Initial State | Result card hidden on load | Result card hidden | `[PASS]` |

## Functional Test Suite

| Test Case | Input Text | Expected | Actual Score & Result | Status |
|-----------|------------|----------|-----------------------|--------|
| **Test 1** | `Urgent: Your PayPal account suspended. Verify at http://192.168.1.1/paypal-secure-login` | Score ≥ 70 HIGH (IP risk + Brand spoofing) | Score **99/100 HIGH RISK** (IP risk + Brand spoofing detected) | `[PASS]` |
| **Test 2** | `https://www.google.com` | Score < 40 LOW | Score **0/100 LOW RISK** | `[PASS]` |
| **Test 3** | `Dear customer your account will be closed within 2 hours. Verify password at http://paypa1.com` | Score ≥ 70 HIGH (Time pressure detected) | Score **100/100 HIGH RISK** (Time pressure + Typosquatting detected) | `[PASS]` |
| **Test 4** | `Hi Uday, meeting tomorrow at 10am` | Score < 40 LOW | Score **0/100 LOW RISK** | `[PASS]` |
| **Test 5** | `Your parcel held. Pay Rs 50 at http://delhivery-track.xyz` | MEDIUM / HIGH | Score **100/100 HIGH RISK** (Parcel hold + Fee demand detected) | `[PASS]` |

## Security & Privacy Checks

| Check | Expected | Result | Status |
|-------|----------|--------|--------|
| Environment File Access | `http://localhost:8000/.env` returns 404 | Returns `404 Not Found` | `[PASS]` |
| Key Leak Prevention | No API keys in DevTools/Responses | Verified zero API key leaks in frontend/backend responses | `[PASS]` |

## Error Handling & Resiliency

| Check | Expected | Result | Status |
|-------|----------|--------|--------|
| Empty Input Validation | Displays "Please enter text" error message, no crash | Displayed "Please enter text" error card cleanly | `[PASS]` |
| VirusTotal 429 Fallback | Returns `{malicious:0, suspicious:0}` fallback on rate limit/timeout | Graceful fallback implemented and verified | `[PASS]` |
| Gemini API Fallback | Fallback to active model chain (`gemini-flash-lite-latest`, `gemini-3.1-flash-lite`, `gemma-4-26b-a4b-it`) | Fast response on active models verified | `[PASS]` |
| Frontend Console Errors | Zero console errors | `TypeError: r.includes` fixed in `app.js` | `[PASS]` |

---

## Final Executive Summary

```text
[PASS] Backend on 8000 running
[PASS] Frontend on 5500 running
[PASS] UI Human Design - No pink/purple gradient
[PASS] Test 1 Phishing URL with IP - Score 99 HIGH
[PASS] Test 2 Legit URL - Score 0 LOW
[PASS] Test 3 Phishing Email Time Pressure - Score 100 HIGH
[PASS] Test 4 Safe Email - Score 0 LOW
[PASS] Test 5 SMS Scam - Score 100 HIGH
[PASS] No API keys leaked
[PASS] No console errors
[PASS] 429 fallback working
ALL TESTS PASSED - READY FOR DEPLOYMENT
```

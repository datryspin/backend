# kiprops-forex — Forex paper trading MVP

Quick paper-trading Forex backend (MVP).
- Language: Python 3.10+
- Framework: FastAPI
- DB: SQLite (for MVP)
- Market data: exchangerate.host (no API key required)
- Mode: Paper trading (simulated fills at current market price)
- Features:
  - Register / login (JWT)
  - Place market orders (buy/sell) for FX pairs (like "EUR/USD")
  - View orders, positions, account cash and P&L
  - Get current rate and historical timeseries

Quick start (local)
1. Clone or add files (this repo).
2. Create and activate a Python venv:
   - python -m venv .venv
   - source .venv/bin/activate (mac/linux) or .venv\Scripts\activate (Windows)
3. Install:
   - pip install -r requirements.txt
4. Copy .env.example -> .env and adjust if needed
5. Run:
   - uvicorn app.main:app --reload
6. API docs:
   - Open http://127.0.0.1:8000/docs

Notes
- This is paper trading only. No real broker integration.
- Default starting cash = 10000 USD. Positions tracked as base currency amounts (e.g., holding EUR when trading EUR/USD).
- Market prices come from exchangerate.host. For production you'd want a reliable paid FX data feed and a broker adapter.

Want next?
- I can scaffold a React/Vite frontend trade ticket & dashboard.
- Add limit orders and a simple background matcher that monitors live prices and executes open limit orders.
- Add an adapter for OANDA (paper/live) or other FX brokers.
- Push this scaffold into `datryspin/backend` (create branch + files) — tell me to proceed.
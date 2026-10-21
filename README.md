# PhishGuard — FT-III Cloud Computing Case Study

## Included
- `main.py`: FastAPI app, responsive UI, rule-based URL screening, API, and scan history.
- `requirements.txt`: Python dependencies.
- `render.yaml`: Render deployment blueprint.
- `Dockerfile`: container deployment option.
- `FT-III_Phishing_URL_Detection.pptx`: presentation is provided separately.

## Important scope note
This starter app uses transparent URL heuristics, **not a trained machine-learning classifier**. It is an academic prototype and does not query live threat-intelligence sources. A low risk score does not guarantee a URL is safe. If your original project has a trained model, integrate it into `analyze_url()` before presenting it as ML-based.

## Run locally (Windows)
1. Install Python 3.10+.
2. Extract this folder and open a terminal in it.
3. Run:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```
4. Open `http://127.0.0.1:8000`.
5. API docs: `http://127.0.0.1:8000/docs`.
6. Health check: `http://127.0.0.1:8000/health`.

## Deploy to Render (public URL)
1. Create a GitHub repository and upload `main.py`, `requirements.txt`, and `render.yaml`.
2. Sign in to Render and connect your GitHub account.
3. Choose **New → Blueprint** (if using `render.yaml`) or **New → Web Service**.
4. Select the repository. If creating a Web Service manually, use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Wait for the deployment to finish; open the generated `onrender.com` URL and test the `/health` endpoint.
6. Free web services may sleep after inactivity, and local files can be lost on restart/redeploy. Do not rely on SQLite for persistent cloud history.

## Persistent database option
For durable scan history, create a managed PostgreSQL database and set `DATABASE_URL` in the service environment to the provider's PostgreSQL connection URL. Make sure the URL uses the SQLAlchemy-compatible `postgresql+psycopg://...` format if required by your provider. Keep database credentials in environment variables, never commit them to GitHub.

## FT-III report/demo checklist
- Capture the deployed home page and a sample scan.
- Test at least 5 URLs you are allowed to inspect; don't use credentials or private URLs.
- Record observed response times and outcomes. Do not copy invented numbers into the report.
- If claiming ML performance, report metrics only from your actual labelled test set (precision, recall, F1, confusion matrix).
- Add the real public URL, deployment screenshots, measured response times, and cost estimate to your slides/report.
- Explain IaaS vs PaaS accurately. Render is a PaaS-style hosting service; AWS Elastic Beanstalk is also a managed application deployment service on AWS infrastructure. Do not claim AWS services are in use unless you actually deploy there.

## Suggested evaluation table
| Test | What to record |
|---|---|
| Valid ordinary URL | Result, score, response time |
| URL with multiple heuristic flags | Result, score, response time |
| Invalid input | Expected validation error |
| History endpoint | Latest scan appears |
| `/health` | HTTP 200 / service status |

## Security and limitations
- Do not use the app as the sole basis for deciding whether to open a URL.
- Never submit passwords, tokens, or confidential URLs.
- This demo performs string-based heuristics and does not fetch or visit the submitted URL.
- For production, add authentication, rate limiting, HTTPS enforcement, stronger validation, logging controls, threat-intelligence feeds, and a properly evaluated model.

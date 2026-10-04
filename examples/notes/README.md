# Example: Notes

A complete app on the framework in about 150 lines: private, encrypted notes per user.

- `backend/notes_app/main.py`: the `AppConfig` (name, terms, retention with 30 backup days, one module)
- `backend/notes_app/models.py`: the `notes` table (cascades with the user, encrypted body)
- `backend/notes_app/api.py`: the routes, protected with `ReadyUser`, with audit events
- `backend/notes_app/migrations/`: the app's own migration branch
- `backend/tests/`: tests using `swf.testing`
- `frontend/src/`: `<SwfApp>` plus one page

Run it locally:

```bash
cd backend
pip install -e ../../../backend -e .
cp ../../../backend/.env.example .env   # set MASTER_KEY, DATABASE_URL, WEBAUTHN_ORIGIN=http://localhost:5174
python -m notes_app.cli migrate
python -m notes_app.cli create-admin <you>
uvicorn notes_app.main:app --port 8001

cd ../frontend && npm install && npm run dev   # http://localhost:5174
```

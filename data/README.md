# data/

This directory is used at runtime for:
- `data/models/` — saved scikit-learn model + scaler (auto-created on first run)
- `data/ids.db` — SQLite alert store (auto-created on first run)

Nothing here needs to be committed or shipped — both are regenerated
automatically the first time you run `main.py` or `streamlit run dashboard/app.py`.

# Results

`quick_results.csv` and `paper_results.csv` are generated locally from real in-memory Client/Server protocol runs.
They are intentionally not stored as reference measurements. Per-scheme detailed logs are written under `logs/`.

`preprocessing_ms` includes database preprocessing and setup/offline key exchange. `query_time_ms` is server online
answer wall-clock time. Query and response sizes are online RPC bytes after setup counters are reset.

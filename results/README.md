# Results

`quick_results.csv` is a release-gate snapshot generated from real in-memory Client/Server protocol runs; `./run.sh`
overwrites it with measurements from the evaluator's machine. `paper_results.csv` is generated only when the paper
runner is invoked. Per-scheme detailed logs are written under `logs/`.

`preprocessing_ms` includes database preprocessing and setup/offline key exchange. `query_time_ms` is server online
answer wall-clock time. Query and response sizes are online RPC bytes after setup counters are reset.

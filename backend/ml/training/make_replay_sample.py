"""Prepare a small, stratified held-out CICIDS sample for in-process replay."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.preprocessing.cicids_pipeline import LABEL_COL, build_full_pipeline  # noqa: E402

DEFAULT_OUTPUT = BACKEND_DIR / "datasets" / "replay" / "replay_sample.csv.gz"


def make_sample(n: int = 3000, seed: int = 42, output: Path = DEFAULT_OUTPUT) -> Path:
    if n < 1:
        raise ValueError("n must be positive")
    # This offline utility constructs the held-out split exactly once per invocation.
    pipeline = build_full_pipeline(seed=seed, sample=1.0, log1p=False)
    test_df = pipeline["test_df"]
    features = pipeline["feat_cols"]
    labels = test_df[LABEL_COL].astype(str)
    from sklearn.model_selection import train_test_split

    take = min(n, len(test_df))
    if take == len(test_df):
        selected = test_df.copy()
    else:
        selected, _ = train_test_split(
            test_df,
            train_size=take,
            random_state=seed,
            stratify=labels,
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    sample = selected[features].copy()
    sample.insert(0, "family", selected[LABEL_COL].astype(str).to_numpy())
    if "Timestamp" in selected.columns:
        sample.insert(0, "Timestamp", selected["Timestamp"].to_numpy())
    sample.to_csv(output, index=False, compression="gzip")
    print(f"Saved {len(sample)} stratified held-out rows to {output}")
    print(f"Family counts: {sample['family'].value_counts().sort_index().to_dict()}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=3000, help="number of held-out rows to save")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    make_sample(args.n, args.seed, args.output)


if __name__ == "__main__":
    main()

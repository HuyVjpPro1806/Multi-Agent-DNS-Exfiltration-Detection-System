"""
tools/dga_model.py
Stage 2 — dga_classifier_agent tool

Uses RandomForest classifier to detect DGA (Domain Generation Algorithm) domains
based on domain features like length, digit ratio, vowel/consonant patterns.

Inference Phase:
    - Load trained RandomForest model
    - Load dns_queries.json
    - Extract 7 features per domain
    - Predict DGA probability (0.0-1.0)
    - Output dga_score for each query
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# Feature names (must match training script)
FEATURE_NAMES = [
    "domain_length",
    "digit_ratio",
    "label_count",
    "subdomain_length",
    "vowel_ratio",
    "consonant_ratio",
    "unique_char_ratio"
]

VOWELS = frozenset("aeiou")


def compute_subdomain_features(subdomain: str) -> Dict[str, float]:
    """
    Compute 4 features from subdomain string.

    Args:
        subdomain: Subdomain string (e.g., "mail", "a3f9bc12")

    Returns:
        Dict with 4 features:
        - subdomain_length
        - vowel_ratio
        - consonant_ratio
        - unique_char_ratio
    """
    length = len(subdomain)
    if length == 0:
        return {
            "subdomain_length": 0.0,
            "vowel_ratio": 0.0,
            "consonant_ratio": 0.0,
            "unique_char_ratio": 0.0,
        }

    alpha_chars = [c for c in subdomain.lower() if c.isalpha()]
    alpha_count = len(alpha_chars)

    vowel_count = sum(1 for c in alpha_chars if c in VOWELS)
    consonant_count = alpha_count - vowel_count
    unique_char_count = len(set(subdomain.lower()))

    vowel_ratio = vowel_count / alpha_count if alpha_count > 0 else 0.0
    consonant_ratio = consonant_count / alpha_count if alpha_count > 0 else 0.0
    unique_char_ratio = unique_char_count / length

    return {
        "subdomain_length": float(length),
        "vowel_ratio": vowel_ratio,
        "consonant_ratio": consonant_ratio,
        "unique_char_ratio": unique_char_ratio,
    }


def extract_features(record: Dict) -> List[float]:
    """
    Extract 7-dimensional feature vector from DNS query record.

    Args:
        record: DNS query dict with fields:
                domain_length, digit_ratio, label_count, subdomain

    Returns:
        List of 7 features in order:
        [domain_length, digit_ratio, label_count,
         subdomain_length, vowel_ratio, consonant_ratio, unique_char_ratio]
    """
    subdomain_feats = compute_subdomain_features(record.get("subdomain", ""))

    return [
        float(record.get("domain_length", 0)),
        float(record.get("digit_ratio", 0)),
        float(record.get("label_count", 0)),
        subdomain_feats["subdomain_length"],
        subdomain_feats["vowel_ratio"],
        subdomain_feats["consonant_ratio"],
        subdomain_feats["unique_char_ratio"],
    ]


def calculate_dga_scores(
    input_path: str,
    output_path: str,
    model_path: str = "models/dga_model.pkl"
) -> Dict:
    """
    Calculate DGA scores for DNS queries using trained RandomForest model.

    Process:
        1. Load trained RandomForest model
        2. Load dns_queries.json
        3. Extract 7 features per domain
        4. Predict DGA probability (0.0-1.0)
        5. Write results to dga_scores.json

    Args:
        input_path:  Path to dns_queries.json (Stage 1 output)
        output_path: Path to write dga_scores.json
        model_path:  Path to trained model pickle

    Returns:
        Dict with processing summary:
        {
            "total_processed": int,
            "high_dga_count": int,
            "output_file": str
        }
    """
    # Load trained model
    model_file = Path(model_path)
    if not model_file.exists():
        log.error(f"Model file not found: {model_path}")
        log.error("Train the model first: python tools/train_dga_model.py")
        return {"error": "model_not_found", "path": str(model_path)}

    log.info(f"Loading model: {model_path}")
    try:
        model = joblib.load(model_file)
        log.info(f"Model loaded successfully (RandomForest, n_estimators={model.n_estimators})")
    except Exception as e:
        log.error(f"Failed to load model: {e}")
        return {"error": "model_load_failed", "detail": str(e)}

    # Load DNS queries
    input_file = Path(input_path)
    if not input_file.exists():
        log.error(f"File not found: {input_path}")
        return {"error": "file_not_found", "path": str(input_path)}

    log.info(f"Reading DNS queries: {input_path}")
    try:
        with open(input_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        log.error(f"Failed to parse JSON: {e}")
        return {"error": "invalid_json", "detail": str(e)}

    # Handle both array and object with "queries" field
    if isinstance(data, dict) and "queries" in data:
        queries = data["queries"]
    elif isinstance(data, list):
        queries = data
    else:
        log.error("Unexpected JSON format (expected array or {queries: [...]})")
        return {"error": "invalid_format", "detail": "No queries found"}

    # Extract features and predict
    results = []
    high_dga_count = 0
    threshold = 0.6  # Scores > 0.6 considered DGA

    log.info(f"Processing {len(queries)} queries...")

    for query in queries:
        # Validate required fields
        if "query_id" not in query or "domain" not in query:
            log.warning(f"Skipping query missing required fields: {query}")
            continue

        try:
            # Extract features
            features = extract_features(query)
            features_array = np.array([features])

            # Predict DGA probability
            dga_proba = model.predict_proba(features_array)[0, 1]  # Probability of class 1 (malicious)
            dga_score = round(float(dga_proba), 4)

            # Track high DGA scores
            if dga_score > threshold:
                high_dga_count += 1

        except Exception as e:
            log.warning(f"Failed to process domain '{query.get('domain', 'N/A')}': {e}")
            dga_score = 0.0  # Default to benign on error

        # Build result entry (matches schema from PLAN.md)
        results.append({
            "query_id": query["query_id"],
            "domain": query["domain"],
            "label": query.get("label", "unknown"),
            "dga_score": dga_score
        })

    total_processed = len(results)
    log.info(f"Processed {total_processed} queries")
    log.info(f"High DGA scores (> {threshold}): {high_dga_count}")

    # Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved → {output_file}")

    return {
        "total_processed": total_processed,
        "high_dga_count": high_dga_count,
        "output_file": str(output_file)
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python dga_model.py <input_json> <output_json> [model_path]")
        print()
        print("Examples:")
        print("  python dga_model.py data/output/dns_queries.json data/output/dga_scores.json")
        print("  python dga_model.py data/output/dns_queries.json data/output/dga_scores.json models/dga_model.pkl")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    model_path = sys.argv[3] if len(sys.argv) > 3 else "models/dga_model.pkl"

    result = calculate_dga_scores(input_path, output_path, model_path)

    if "error" not in result:
        print(f"[OK] Processed {result['total_processed']} queries")
        print(f"[OK] Found {result['high_dga_count']} high DGA scores")
        print(f"[OK] Output: {result['output_file']}")
    else:
        print(f"[ERROR] {result}")
        sys.exit(1)

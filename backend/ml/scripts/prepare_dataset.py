import os
import pandas as pd
import numpy as np

def generate_dataset(output_path="backend/ml/data/packages_dataset.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    np.random.seed(42)
    n_samples = 2000

    # Features:
    # 1. age_days (Older packages are generally safer, newer are more suspicious)
    # 2. release_frequency (Releases per year)
    # 3. dependency_count (Number of direct dependencies)
    # 4. dependency_growth (Number of dependencies added recently)
    # 5. maintainer_count (Number of maintainers)
    # 6. maintainer_changes (Number of maintainer changes in last year)
    # 7. has_install_script (0 or 1, installation hooks are highly associated with malicious packages)
    # 8. obfuscation_score (0.0 to 1.0, obfuscated code indicator)
    # 9. network_call_count (0 to 10, references to network APIs like socket, http, child_process)
    # 10. vulnerability_history_count (Number of past CVEs)
    # 11. license_change_indicator (0 or 1, sudden license changes)
    # 12. reputation_score (0 to 100, based on downloads/stars)

    # Class 0: Normal Packages (90%)
    n_normal = int(n_samples * 0.90)
    normal_data = {
        "age_days": np.random.randint(180, 3000, n_normal),
        "release_frequency": np.random.uniform(1.0, 24.0, n_normal),
        "dependency_count": np.random.randint(0, 15, n_normal),
        "dependency_growth": np.random.randint(0, 3, n_normal),
        "maintainer_count": np.random.randint(2, 20, n_normal),
        "maintainer_changes": np.random.choice([0, 1, 2], size=n_normal, p=[0.8, 0.15, 0.05]),
        "has_install_script": np.random.choice([0, 1], size=n_normal, p=[0.95, 0.05]),
        "obfuscation_score": np.random.exponential(0.02, n_normal),
        "network_call_count": np.random.randint(0, 3, n_normal),
        "vulnerability_history_count": np.random.randint(0, 4, n_normal),
        "license_change_indicator": np.random.choice([0, 1], size=n_normal, p=[0.98, 0.02]),
        "reputation_score": np.random.randint(50, 100, n_normal),
        "is_suspicious": 0
    }
    # Cap obfuscation at 1.0
    normal_data["obfuscation_score"] = np.minimum(normal_data["obfuscation_score"], 1.0)

    # Class 1: Suspicious / Malicious Packages (10%)
    n_suspicious = n_samples - n_normal
    suspicious_data = {
        "age_days": np.random.randint(1, 150, n_suspicious), # Very young
        "release_frequency": np.random.uniform(0.1, 5.0, n_suspicious),
        "dependency_count": np.random.randint(5, 50, suspicious_data := n_suspicious), # Often high direct count
        "dependency_growth": np.random.randint(3, 20, n_suspicious), # Rapid addition
        "maintainer_count": np.random.randint(1, 2, n_suspicious), # Single maintainer
        "maintainer_changes": np.random.choice([0, 1, 2, 3], size=n_suspicious, p=[0.3, 0.4, 0.2, 0.1]), # Recent changes
        "has_install_script": np.random.choice([0, 1], size=n_suspicious, p=[0.2, 0.8]), # High rate of install scripts
        "obfuscation_score": np.random.uniform(0.4, 1.0, n_suspicious), # Obfuscated code
        "network_call_count": np.random.randint(3, 10, n_suspicious), # Frequent socket calls/obfuscated code downloaders
        "vulnerability_history_count": np.random.randint(0, 2, n_suspicious),
        "license_change_indicator": np.random.choice([0, 1], size=n_suspicious, p=[0.7, 0.3]),
        "reputation_score": np.random.randint(0, 30, n_suspicious), # Low reputation
        "is_suspicious": 1
    }

    df_normal = pd.DataFrame(normal_data)
    df_suspicious = pd.DataFrame(suspicious_data)
    df = pd.concat([df_normal, df_suspicious]).reset_index(drop=True)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"Dataset generated at {output_path} with {len(df)} rows.")

if __name__ == "__main__":
    generate_dataset()

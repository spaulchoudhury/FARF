"""
Statistical Validation Workflow helpers
============================================
Source diagram: Statistical_Validation_Workflow.svg (mirrors Fig 7.11 /
Tab 7.9 in the research proposal).

Each function below corresponds to one node in the diagram:

    Repeated Experimental Trials -> Data Collection
        -> Descriptive Statistics (Mean, SD, 95% CI)
        -> Normality Test -> {Normal: Paired t-test, Non-normal: Wilcoxon}
        -> Significance Analysis -> Effect Size -> Statistical Conclusions

        (parallel branch)
        Predicted FARS + Observed Attack Outcomes -> Pearson Correlation
        -> MAE & RMSE -> Statistical Conclusions
"""
import math

import numpy as np
from scipy import stats


def descriptive_statistics(sample: list[float]) -> dict:
    """Diagram node: 'Descriptive Statistics — Mean, SD, 95% CI'."""
    arr = np.asarray(sample, dtype=float)
    n = len(arr)
    mean = float(np.mean(arr))
    sd = float(np.std(arr, ddof=1)) if n > 1 else 0.0
    if n > 1:
        sem = sd / math.sqrt(n)
        ci = stats.t.interval(0.95, df=n - 1, loc=mean, scale=sem) if sem > 0 else (mean, mean)
    else:
        ci = (mean, mean)
    return {"n": n, "mean": mean, "sd": sd, "ci_95": (float(ci[0]), float(ci[1]))}


def normality_test(sample: list[float]) -> dict:
    """Diagram node: 'Normality Test -> Normal / Non-normal'.
    Uses Shapiro-Wilk, the standard small-sample normality test."""
    arr = np.asarray(sample, dtype=float)
    if len(arr) < 3 or np.allclose(arr, arr[0]):
        # Shapiro-Wilk is undefined for n<3 or constant data; treat as non-normal
        return {"statistic": None, "p_value": 0.0, "is_normal": False}
    statistic, p_value = stats.shapiro(arr)
    return {"statistic": float(statistic), "p_value": float(p_value), "is_normal": p_value > 0.05}


def paired_significance_test(sample_a: list[float], sample_b: list[float], is_normal: bool) -> dict:
    """Diagram node: 'Paired t-test / Wilcoxon Signed-Rank Test' -> 'Significance Analysis'."""
    a, b = np.asarray(sample_a, dtype=float), np.asarray(sample_b, dtype=float)
    diffs = a - b
    if np.allclose(diffs, 0):
        return {"test": "none (identical samples)", "statistic": 0.0, "p_value": 1.0, "significant": False}
    if np.std(diffs, ddof=1) == 0:
        # every paired difference is identical and non-zero: the effect is
        # deterministic/categorical, so a variance-based test statistic is
        # undefined -- report the (maximal) significance explicitly instead
        # of calling scipy (which would otherwise emit a divide-by-zero warning).
        return {"test": "deterministic_constant_effect", "statistic": float("inf"),
                "p_value": 0.0, "significant": True}
    if is_normal:
        statistic, p_value = stats.ttest_rel(a, b)
        test_name = "paired_t_test"
    else:
        try:
            statistic, p_value = stats.wilcoxon(a, b)
            test_name = "wilcoxon_signed_rank"
        except ValueError:
            statistic, p_value = stats.ttest_rel(a, b)
            test_name = "paired_t_test_fallback"
    return {"test": test_name, "statistic": float(statistic), "p_value": float(p_value),
            "significant": bool(p_value < 0.05)}


def effect_size_cohens_d(sample_a: list[float], sample_b: list[float]) -> float:
    """Diagram node: 'Effect Size' (Cohen's d for paired samples)."""
    diffs = np.asarray(sample_a, dtype=float) - np.asarray(sample_b, dtype=float)
    sd = np.std(diffs, ddof=1)
    if sd == 0:
        return 0.0
    return float(np.mean(diffs) / sd)


def statistical_conclusion(desc_a: dict, desc_b: dict, sig: dict, effect_size: float,
                            label_a: str = "FARF-enabled", label_b: str = "baseline (no-FARF)") -> str:
    """Diagram node: 'Statistical Conclusions'."""
    direction = "higher" if desc_a["mean"] > desc_b["mean"] else "lower"
    verdict = "statistically significant" if sig["significant"] else "not statistically significant"
    return (f"{label_a} (mean={desc_a['mean']:.2f}, 95% CI={desc_a['ci_95']}) was {direction} than "
            f"{label_b} (mean={desc_b['mean']:.2f}, 95% CI={desc_b['ci_95']}); "
            f"{sig['test']} p={sig['p_value']:.4f} ({verdict}); Cohen's d={effect_size:.3f}.")


def fars_predictive_validity(predicted_fars: list[float], observed_resilience: list[float]) -> dict:
    """
    Diagram (parallel) branch: 'Predicted FARS + Observed Attack Outcomes
    -> Pearson Correlation -> MAE & RMSE'.
    """
    pred = np.asarray(predicted_fars, dtype=float)
    obs = np.asarray(observed_resilience, dtype=float)
    if len(pred) < 2 or np.allclose(pred, pred[0]) or np.allclose(obs, obs[0]):
        r, p_value = 0.0, 1.0
    else:
        r, p_value = stats.pearsonr(pred, obs)
    mae = float(np.mean(np.abs(pred - obs)))
    rmse = float(np.sqrt(np.mean((pred - obs) ** 2)))
    return {"pearson_r": float(r), "p_value": float(p_value), "mae": mae, "rmse": rmse}


def fars_discriminative_validity(predicted_fars: list[float], contained: list[bool]) -> dict:
    """
    Companion metric to fars_predictive_validity(), added because Pearson
    correlation is unreliable under range restriction (see
    test_04_statistical_validation.py's docstring history -- the original
    severity sampling never actually reached the containment/escape
    boundary at all, so EVERY trial had the same binary outcome and no
    correlation coefficient computed on that data could mean anything,
    regardless of how good FARS actually is).

    ROC AUC asks a more targeted, more robust question: treating
    'contained' vs. 'not contained' as a binary outcome, does a HIGHER
    FARS score reliably rank contained trials above uncontained ones?
    This degrades more gracefully than Pearson r when the outcome
    variable is imbalanced (though it still needs BOTH classes present
    at all -- with zero trials of one outcome, AUC is undefined, same
    fundamental limit as correlation).
    """
    from sklearn.metrics import roc_auc_score
    pred = np.asarray(predicted_fars, dtype=float)
    y = np.asarray(contained, dtype=int)
    if len(set(y.tolist())) < 2:
        return {"auc": None, "reason": "only one outcome class present -- AUC undefined"}
    auc = float(roc_auc_score(y, pred))
    return {"auc": auc, "reason": None}

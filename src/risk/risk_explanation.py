"""
UniShield AI -- Risk Explanation Generator
=========================================
Generates human-readable explanations based on the computed risk factors
without claiming unverified certainties (like "Host is compromised").
"""

from typing import List
from src.correlation.correlation_models import Incident, RiskFactor

def generate_risk_explanation(incident: Incident, factors: List[RiskFactor], level: str) -> str:
    """
    Produce a transparent explanation for the assigned risk level.
    """
    parts = []
    
    # 1. Base statement
    source_str = "a single internal source" if len(incident.sources) == 1 else "multiple internal sources"
    base_msg = f"{level.capitalize()} risk was assigned because {source_str} generated "
    
    # 2. Extract behaviors from factors
    behaviors = []
    has_temporal = False
    has_progression = False
    has_corroboration = False
    
    for f in factors:
        if f.factor == "Temporal Correlation":
            has_temporal = True
        elif f.factor == "Attack Progression":
            has_progression = True
        elif f.factor == "Corroboration Bonus":
            has_corroboration = True
        elif "Base Risk" not in f.factor and "Confidence" not in f.factor and "Metadata" not in f.factor:
            # It's a detector threat class
            behaviors.append(f.factor)
            
    if not behaviors:
        behaviors = ["suspicious network behavior"]
        
    if len(behaviors) == 1:
        base_msg += f"{behaviors[0]}."
    else:
        # e.g. "Reconnaissance, DGA, and Exfiltration."
        base_msg += f"{', '.join(behaviors[:-1])}, and {behaviors[-1]}."
        
    parts.append(base_msg)
    
    # 3. Add Context Modifiers
    context = []
    if has_temporal:
        context.append("within a tightly correlated time window")
    if has_corroboration:
        context.append("flagged by multiple independent detectors")
        
    if context:
        parts.append(f"These events occurred {' and '.join(context)}.")
        
    # 4. Progression inference
    if has_progression:
        parts.append("The sequence of these indicators is consistent with potentially malicious multi-stage activity.")
    elif level in ["HIGH", "CRITICAL"]:
        parts.append("The observed indicators form a potentially related sequence of high-risk behavior.")
        
    return " ".join(parts)

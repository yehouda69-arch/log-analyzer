from pydantic import BaseModel
from typing import List, Literal


Urgency = Literal["low", "medium", "high"]


class Hypothesis(BaseModel):
    rank: int
    description: str
    justification: str


class NextStep(BaseModel):
    text: str
    urgency: Urgency


class LogAnalysisResponse(BaseModel):
    confirmed_facts: List[str]
    primary_failure: str
    root_cause: str
    unknowns: List[str]
    hypotheses_ranked: List[Hypothesis]
    next_steps: List[NextStep]
    contradictions: List[str]
    severity_score: int  # 1=Low, 2=Medium, 3=High
    severity_label: str  # "Low" / "Medium" / "High"

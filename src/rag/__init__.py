"""Pipeline RAG completo: retrieval -> prompt -> geracao citada (Fase 5)."""

from .pipeline import CitationCheck, RagAnswer, RagPipeline, check_citations
from .prompt import SYSTEM_PROMPT, build_context, build_prompt, format_rule

__all__ = [
    "SYSTEM_PROMPT",
    "CitationCheck",
    "RagAnswer",
    "RagPipeline",
    "build_context",
    "build_prompt",
    "check_citations",
    "format_rule",
]

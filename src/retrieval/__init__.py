"""Busca hibrida: filtro por metadado + vetorial + full-text (Fase 4)."""

from .fusion import RRF_K, FusedResult, RankedList, reciprocal_rank_fusion
from .query import ParsedQuery, build_tsquery, extract_lexical_terms, parse_query
from .search import HybridRetriever, RetrievedRule, SearchFilters, SearchResponse

__all__ = [
    "RRF_K",
    "FusedResult",
    "HybridRetriever",
    "ParsedQuery",
    "RankedList",
    "RetrievedRule",
    "SearchFilters",
    "SearchResponse",
    "build_tsquery",
    "extract_lexical_terms",
    "parse_query",
    "reciprocal_rank_fusion",
]

"""Estratégia de chunking: o que vira vetor e o que fica como contexto."""

from .chunk import (
    MAX_CONTEXT_DATA_SOURCE_CHARS,
    MAX_QUERY_CHARS,
    TRUNCATION_MARKER,
    RuleChunk,
    build_embedding_text,
    chunk_rule,
    select_context_data_sources,
    truncate_query,
)

__all__ = [
    "MAX_CONTEXT_DATA_SOURCE_CHARS",
    "MAX_QUERY_CHARS",
    "TRUNCATION_MARKER",
    "RuleChunk",
    "build_embedding_text",
    "chunk_rule",
    "select_context_data_sources",
    "truncate_query",
]

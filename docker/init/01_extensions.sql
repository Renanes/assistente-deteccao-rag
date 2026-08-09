-- Habilita a extensão pgvector no banco de dados do projeto.
-- Executado automaticamente pelo entrypoint oficial do Postgres na primeira
-- inicialização do volume (docker-entrypoint-initdb.d).
CREATE EXTENSION IF NOT EXISTS vector;

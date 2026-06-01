# Novas Atualizações — AEGIS Threat Intelligence

> Registro das melhorias de **confiabilidade dos dados** e **correlação** implementadas, com o estado anterior, o estado atual, o que mudou e o que melhorou. Foco no diferencial do projeto: transformar dado bruto em inteligência confiável e acionável para o SOC, **sem redundância de fontes**.

**Data:** 2026-05-31
**Commits:** `f26f41b`, `0d4bf50`, `0d5d38e`, `1d476af`, `a75719c`

---

## Visão geral

Foram implementadas **5 frentes**, todas validadas localmente (`.venv` + SQLite, sem tocar na produção do Render) e versionadas:

| # | Frente | Impacto principal |
|---|---|---|
| 1 | OTX estruturado + DShield + Kill Chain real | Correlação com ataques reais e atribuição de adversário |
| 2 | Orquestração Airflow | Pipeline diário automatizado e seguro |
| 3 | Corroboração por família de fonte independente | Acaba com a redundância inflando confiança |
| 4 | EPSS (probabilidade de exploração) | Priorização real de CVEs |
| 5 | Shodan InternetDB | Superfície real de cada IP (portas/tags/vulns) |

---

## 1. OTX estruturado + DShield + Kill Chain real

### Antes
- O collector do **OTX** reduzia cada pulse a `description = nome do pulse`. Todo o resto era **descartado**: o ator (`adversary`), as técnicas ATT&CK atribuídas por analista (`attack_ids`), a família de malware e o id da campanha.
- O `TYPE_MAP` do OTX ignorava **CVE, FileHash-SHA1 e IPv6** — esses IOCs eram silenciosamente jogados fora.
- A **Kill Chain** era reconstruída por *keyword-matching* em texto livre (`"command"` casava com "command injection"; `"auth"` casava com "author") — atribuição de técnica não confiável.
- Para IPs, a severidade era um carimbo `HIGH` fixo → o componente **T do score colapsava em ~70 para quase todo IP** (sem poder discriminar IP perigoso de ruído).
- A janela temporal de correlação usava `first_seen`, mas as blocklists setavam `first_seen = hoje` (data de ingestão, não do evento) → "mesma janela de ataque" não significava nada.

### Agora
- **OTX estruturado:** cada pulse é tratado como uma **campanha real** — extrai `adversary`, `attack_ids` (técnicas ATT&CK reais), `campaign_id` e malware. Tipos antes descartados (CVE, SHA1, IPv6) foram recuperados (~300 IOCs a mais por execução).
- **DShield / SANS ISC (novo collector):** telemetria de ataque real de milhares de sensores de firewall. Traz **volume de ataques por IP** e **datas reais de evento**.
- **Kill Chain confiável:** o mapeador prioriza os `attack_ids` reais do OTX sobre o keyword-matching; persiste a cadeia completa (`mitre_techniques`).
- **Correlação por campanha real:** IOCs que compartilham `campaign_id` co-ocorreram no mesmo ataque reportado — prioridade sobre a heurística de /24.

### O que mudou / melhorou
- **3 colunas novas:** `campaign_id`, `adversary`, `mitre_techniques` (migração segura, expostas ao drawer via `SELECT *`).
- O **T dos IPs voltou a discriminar**: o `abuse_score` do DShield vai de 83 a 100, com 16 valores distintos (vs. carimbo único antes).
- A **janela temporal** passou a funcionar para IPs do DShield (datas reais).
- **Validação:** adversários reais no banco — Silver Fox, SHADOW-EARTH-053, ClickFix, Static Tundra, Kimsuky. A campanha Silver Fox ligou o domínio `obfuscate.io` a 10 peers reais (hashes + URL) que co-ocorreram no mesmo ataque.

---

## 2. Orquestração via Apache Airflow

### Antes
- O README prometia "orquestração via Airflow (08:00 UTC)", mas **não havia Airflow no repositório** — nenhum DAG, nenhum `docker-compose`. O pipeline rodava só manualmente.

### Agora
- DAG versionado em `dags/aegis_pipeline_dag.py`, agendado diariamente às **08:00 UTC**.
- Modelo de execução correto para o deploy: o DAG **dispara a produção via `POST /api/pipeline/run`** (HTTP) e acompanha a conclusão pelo `/health`. (Rodar localmente escreveria no SQLite local, não no Postgres de produção.)

### O que mudou / melhorou
- A **chave de API saiu do código**: é lida em runtime de uma Airflow Variable (`aegis_api_key`) ou env — **nunca hardcoded**. (A versão original tinha a `AEGIS_API_KEY` de produção em texto puro.)
- `base_url` configurável via Variable `aegis_base_url`.
- `.gitignore` passou a ignorar artefatos do Airflow, `.venv` e backups locais.
- O Airflow roda em **ambiente separado** do projeto (evita conflito de dependências, ex.: versão do SQLAlchemy).

> ⚠️ **Ação de segurança recomendada:** a chave de produção que estava em texto puro deve ser **rotacionada** no Render e registrada como Airflow Variable.

---

## 3. Corroboração por família de fonte independente

*Esta é a melhoria mais direta ao pedido "sem redundância".*

### Antes
- O componente **C (corroboração)** contava **nomes de feed**: 1 fonte → C=33, 2 → C=66, 3+ → C=100.
- Problema: **ThreatFox, URLhaus e Feodo são todos da abuse.ch** (mesma organização, telemetria sobreposta). Três feeds da abuse.ch concordando davam **C=100**, como se fossem 3 confirmações independentes. Isso inflava a confiança com **redundância**.

### Agora
- O C conta **famílias de telemetria independente**, não feeds:

| Família | Fontes |
|---|---|
| `abuse.ch` | ThreatFox, URLhaus, Feodo |
| `honeypot` | DShield, GreyNoise, EmergingThreats |
| `autoritativa` | CISA-KEV |
| `reputacao` | AbuseIPDB |
| `comunidade` | AlienVault OTX |

- Fonte não mapeada conta como família própria (continua independente).
- O breakdown ficou **mais auditável**: mostra `familias`, `familias_count` e a justificativa expõe a redundância — *"2 feeds, mas 1 família independente (feeds redundantes não elevam o C)"*.

### O que mudou / melhorou
- `calculate_score_breakdown` aceita `sources=` (preferido) e deriva C de famílias.
- Os 3 caminhos de cálculo (coleta, corroboração, recálculo) passam o conjunto de fontes.
- **Backfill idempotente** (`backfill_corroboration_families`) corrige os registros multi-fonte já no banco.
- **Validação:**
  - 3 feeds abuse.ch → **C=33** (antes 100)
  - ThreatFox+URLhaus → **66 → 33**
  - OTX+CISA e ET+Feodo → mantêm **66** (2 famílias reais)

---

## 4. EPSS — probabilidade de exploração de CVE

### Antes
- O componente **T dos CVEs** usava só o CVSS (severidade *se* explorado). CVEs sem CVSS recebiam **T=80 fixo para todos** — sem discriminação.
- Não havia nenhum sinal de **probabilidade de exploração** (qual CVE está sendo de fato explorado).

### Agora
- Integração com o **EPSS (FIRST.org)**: probabilidade de exploração nos próximos 30 dias. Gratuito, sem key, API em lote.
- Complementa o CISA-KEV (já explorado) e o CVSS (severidade).
- O EPSS é **sempre exposto** no breakdown (`type_severity.epss`) para priorização do analista.

### O que mudou / melhorou (sem quebrar o sistema)
- **2 colunas novas:** `epss_score`, `epss_percentile`.
- `epss_enricher` (lote, para CVEs novos no pipeline) + `scripts/enrich_epss.py` (backfill dos existentes).
- **Regra do T (não-quebra):**
  - CVSS presente → `T = CVSS×10` **inalterado** (zero regressão).
  - CVSS ausente + EPSS → `T = max(60, percentil×100)` (antes era 80 fixo).
  - Sem ambos → 80 (fallback mantido).
- **Validação:** 1607/1607 CVEs enriquecidos; **969 (60%) sem CVSS saíram do T=80 fixo**.
  - Exemplo de ouro: **CVE-2023-23752 (Joomla)** tem CVSS apenas 5.3 (médio), mas **EPSS percentil 100%** — ativamente explorado. Pelo CVSS o analista deixaria de lado; o EPSS revela que é alvo prioritário.

---

## 5. Shodan InternetDB — superfície real do IP

### Antes
- Os IPs não tinham nenhuma informação de **superfície de exposição** (portas abertas, serviços, vulnerabilidades). O contexto do atacante era limitado.

### Agora
- Integração com o **Shodan InternetDB** (gratuito, sem key): para cada IP, traz **portas abertas, tags (scanner/compromised/c2...), CVEs expostos e hostnames**.
- **Não redundante:** a live-enrichment do drawer usa AbuseIPDB; o InternetDB cobre uma dimensão diferente (superfície/serviços).

### O que mudou / melhorou
- **Coluna nova:** `shodan_data` (JSON), persistida e parseada de volta para o drawer/API.
- `shodan_enricher` faz consultas **concorrentes** (ThreadPool, 10 workers, timeout 6s, trata 404) — ~520 IPs em segundos.
- É **enriquecimento de contexto — não altera o score** (mantém o sistema estável).
- **Validação:** 258/520 IPs com dados; tags reais (scanner=105, cloud, eol-product, vpn); um IP com **427 vulnerabilidades conhecidas**.

---

## Resumo do impacto

| Componente do score | Antes | Agora |
|---|---|---|
| **S** (confiabilidade de fonte) | hardcoded por feed | + DShield (78) mapeado em famílias |
| **C** (corroboração) | conta feeds (redundância infla) | **conta famílias independentes** |
| **T** — IP | carimbo HIGH ≈ 70 fixo | **volume de ataque real (DShield)** |
| **T** — CVE | CVSS, ou 80 fixo sem CVSS | CVSS, ou **EPSS** sem CVSS |
| **Kill Chain** | keyword-matching frágil | **técnicas ATT&CK reais (OTX)** |
| **Correlação** | heurística de /24 + país | **campanha real (OTX pulse)** |
| **Contexto de IP** | país + ASN | + **portas/tags/vulns (Shodan)** |
| **Orquestração** | manual | **Airflow diário (08:00 UTC)** |

### Fontes (todas gratuitas, sem redundância)
- **Adicionadas:** DShield/SANS ISC (telemetria de ataque), EPSS/FIRST.org (predição de exploração), Shodan InternetDB (superfície de IP).
- **Aproveitadas melhor:** AlienVault OTX (campanha + ator + ATT&CK estruturados).

### Frentes futuras sugeridas
1. **Spamhaus DROP/EDROP** — netblocks bulletproof (ground-truth para correlação por ASN).
2. **S empírico** — confiabilidade de fonte derivada do histórico de falso-positivo, em vez de valores fixos.

---

## Validação e segurança

- Tudo testado localmente com `.venv` contra o SQLite local — **a produção do Render não foi tocada**.
- Backups por etapa: `data/iocs.db.bak_otxds`, `.bak_families`, `.bak_epss`, `.bak_shodan`.
- Todas as mudanças no banco são **migrações aditivas e compatíveis** (colunas novas via `ADD COLUMN`, sem alterar dados existentes).
- Nenhum segredo foi versionado; a chave de API do Airflow vem de variável de ambiente.

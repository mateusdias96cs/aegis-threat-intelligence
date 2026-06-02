# AEGIS Threat Intelligence — Atualizações e Funcionalidades

> Documento consolidado de **tudo** que o AEGIS implementa: arquitetura, modelo de
> pontuação, módulos, fontes, enriquecimento, correlação, visualizações e as
> melhorias mais recentes de confiabilidade e cruzamento de dados.
>
> **Tese do projeto:** transformar **IOC bruto** em **inteligência confiável,
> contextualizada e acionável** para o SOC — sem redundância de fontes, com
> dados de qualidade e correlação real entre indicadores.

**Última atualização:** 2026-06-02

---

## 1. Visão geral

O AEGIS é uma plataforma de **Threat Intelligence** que coleta, normaliza,
enriquece, pontua e correlaciona **IOCs** (Indicators of Compromise — IPs,
domínios, URLs, hashes e CVEs) de múltiplas fontes públicas, expondo tudo num
dashboard analítico e numa API.

### Stack
- **Backend:** FastAPI + SQLAlchemy 2.x
- **Banco:** PostgreSQL (produção) / SQLite (local) — mesmo código, migrações aditivas
- **Orquestração:** Apache Airflow (pipeline diário às 08:00 UTC)
- **Frontend:** dashboard HTML/JS (dark analytics) com grafo de correlação (vis.js)
- **Observabilidade:** Sentry
- **Deploy:** Render

### Pipeline (visão de alto nível)
```
Coleta → Proveniência (sightings) → Deduplicação → Enriquecimento
      → Warninglists (FP) → Classificação/Score → MITRE ATT&CK
      → Completude de Contexto → Persistência → Corroboração
      → Decay BioSec → Recálculo → Relatório
```

---

## 2. Modelo de Pontuação BioSec (Score de Confiança)

Cada IOC recebe um **score de confiança (0–100)** com fórmula auditável e
transparente:

```
Score = (S × 0.40) + (C × 0.30) + (T × 0.30)
```

| Componente | Significado | Como é calculado |
|---|---|---|
| **S** | Confiabilidade da Fonte | Reputação por feed (CISA-KEV=100 … OTX=55); usa a **fonte mais confiável** que reportou o IOC |
| **C** | Corroboração | **Famílias de telemetria independente** (não contagem bruta de feeds) |
| **T** | Severidade por Tipo | CVE → CVSS×10 ou EPSS; IP → score de abuso/ataque; hash/url/domínio → base por tipo |

Todo IOC guarda um **`score_breakdown`** completo (JSON) explicando como cada
ponto foi calculado — exposto no painel lateral (drawer) para o analista.

### 2.1 Corroboração por FAMÍLIA independente (anti-redundância)
Vários feeds da **mesma organização** (ThreatFox + URLhaus + Feodo são todos da
abuse.ch) **não** são confirmações independentes. O componente **C** conta
**famílias de telemetria distinta**, não nomes de feed:

| Família | Fontes |
|---|---|
| `abuse.ch` | ThreatFox, URLhaus, Feodo |
| `honeypot` | DShield, GreyNoise, EmergingThreats |
| `autoritativa` | CISA-KEV |
| `reputacao` | AbuseIPDB |
| `comunidade` | AlienVault OTX |

Três feeds da abuse.ch concordando dão **C=33** (1 família), não C=100. O
breakdown expõe a redundância de forma auditável.

---

## 3. Módulo BioSec Decay (memória imunológica)

Filosofia: **IOCs nunca são deletados** — o score **decai com o tempo**, como a
memória imunológica. Reaparecimento dispara reativação.

- **Decaimento exponencial:** `score = score_original × e^(−0.693 × dias / meia_vida)`
- **Meias-vidas por tipo:** IP=15d, URL=7d, domínio=30d, hash=180d, CVE=365d
- **Estados:** `ACTIVE` (≥20%), `DECAYED` (5–20%), `HISTORICAL` (<5%),
  `REACTIVATED` (reapareceu após inatividade — recebe bônus de confiança)
- **Reativação:** atualiza `last_seen`, incrementa contador e aplica bônus
  proporcional ao número de reaparições

---

## 4. Módulo de Contextualização

Transforma cada IOC numa ficha rica, navegável pelo drawer lateral:

- **Marcação de Falso-Positivo** (manual): o analista marca um IOC como FP, com
  nota; o score é reduzido em 80% e o status vira `FALSE_POSITIVE` (reversível).
- **Correlação de campanha:** "Outros IOCs desta campanha" (peers reais).
- **Enriquecimento ao vivo:** consulta sob demanda no drawer (ex.: AbuseIPDB).
- **Drawer completo:** Score & Confiança, Origem & Confirmação, Contexto de
  Ataque (MITRE), Histórico, Ações (copiar, VirusTotal, Shodan, marcar FP).

---

## 5. Fontes de Coleta (todas gratuitas, sem redundância)

| Fonte | O que traz |
|---|---|
| **CISA-KEV** | Catálogo oficial de vulnerabilidades exploradas ativamente |
| **AlienVault OTX** | Campanhas estruturadas: ator, técnicas ATT&CK, malware, pulse id |
| **ThreatFox** (abuse.ch) | IOCs crowdsourced verificados |
| **URLhaus** (abuse.ch) | URLs maliciosas |
| **Feodo Tracker** (abuse.ch) | C2 de botnets financeiros |
| **AbuseIPDB** | Reputação de IPs |
| **DShield / SANS ISC** | Telemetria real de ataque (milhares de sensores de firewall) |
| **Emerging Threats** | IPs maliciosos |
| **GreyNoise** | Scanners de internet (requer API key) |
| **MalwareBazaar** (abuse.ch) | Contexto de famílias de malware por hash |

### Kill Chain MITRE ATT&CK confiável
A reconstrução da Kill Chain prioriza as **técnicas ATT&CK reais** atribuídas por
analista (via OTX `attack_ids`) sobre heurísticas frágeis de keyword-matching.

---

## 6. Enriquecimento (Enrichers)

| Enricher | Dimensão adicionada |
|---|---|
| **GeoIP2 (MaxMind)** | País + **ASN** do IP (correlação por infraestrutura) |
| **Shodan InternetDB** | Superfície do IP: portas abertas, tags, CVEs expostos, hostnames (grátis, sem key) |
| **EPSS (FIRST.org)** | Probabilidade de exploração do CVE nos próximos 30 dias |
| **MalwareBazaar** | Família/tipo/tags do malware por hash |

### EPSS — priorização real de CVE
Quando o CVSS está ausente, o **percentil EPSS** discrimina a prioridade (antes,
todos recebiam T=80 fixo). Exemplo de ouro: **CVE-2023-23752 (Joomla)** tem CVSS
apenas 5.3, mas EPSS percentil 100% — está sendo ativamente explorado.

---

## 7. Completude de Contexto

Métrica que quantifica **quantas dimensões de contexto** um IOC tem preenchidas,
relativo ao que é alcançável para o seu tipo (uma hash não tem geo; um CVE não
tem ASN). Materializa o diferencial do AEGIS — "IOC bruto" vs. "IOC refinado"
vira um número (`context_score`), com badge no drawer.

---

## 8. Correlação de IOCs (cruzamento de dados)

O cruzamento de dados acontece em vários níveis, do mais forte ao heurístico:

1. **Campanha real (OTX pulse):** IOCs que compartilham `campaign_id`
   co-ocorreram no mesmo ataque reportado (sinal mais confiável).
2. **Atribuição (adversário):** IOCs do mesmo ator, mesmo em campanhas distintas.
3. **Infraestrutura (ASN + /24):** IPs na mesma rede/sub-rede.
4. **Corroboração multi-fonte:** o mesmo IOC visto por famílias independentes.

### Painel de Panorama (Threat Overview)
KPIs e rankings: top campanhas, top adversários, top ASNs, top países — cada um
clicável, abrindo o grafo filtrado.

### Grafo de Correlação (Correlation Graph)
Grafo navegável de nós (IOCs) e hubs (campanha, ator, ASN, sub-rede). Ver
detalhe das melhorias na seção 9 (P3).

---

## 9. Melhorias recentes — Confiabilidade e Cruzamento de Dados

Frente dedicada a **refinar os dados, aumentar a confiabilidade e melhorar a
correlação**, baseada em referências da indústria (NATO/Admiralty, MISP, SANS) e
de engenharia de dados (qualidade, proveniência, fusão por grafo).

### P1 — Tabela de Sightings (proveniência / linhagem)
Registra **quem** (fonte) viu **qual** IOC, **quando** (primeira/última
observação) e **quantas vezes**, antes da deduplicação colapsar as duplicatas.

- Nova tabela `sightings(value, source, first_seen, last_seen, seen_count)`.
- Upsert idempotente por execução; exposta na nova seção **"Proveniência por
  Fonte"** do drawer (linha do tempo de coleta).
- **Funda** a confiabilidade de fonte empírica (frente futura), a atualidade
  (timeliness) por fonte e a corroboração com datas reais.

### P2 — Warninglists + Tranco (redução de falso-positivo)
Cruza cada IOC contra listas curadas de **infraestrutura legítima conhecida** —
faixas de cloud (AWS, Azure, GCP, Cloudflare, Akamai, Fastly), resolvers DNS
públicos, redes reservadas e domínios populares (**Tranco** top-10k).

- **Não deleta:** marca `fp_warning` (qual lista casou) e **rebaixa o score em
  50%** (provável FP), mantendo o IOC visível e auditável.
- Banner **"Provável falso-positivo"** no drawer.
- Listas mantidas em `data/warninglists/` (formato MISP); scripts de atualização
  (`refresh_warninglists`) e backfill (`backfill_warninglists`).
- Impacto medido: centenas de IOCs de infra benigna deixam de inflar a fila do
  analista; domínios marcados caem para ~metade do score.

### P3 — Grafo Tipado + Detecção de Comunidades
Eleva o grafo de hub-and-spoke estático para um modelo com **arestas tipadas** e
**community detection (Louvain)**.

- Nova aresta/hub **"Ator"** (atribuição): liga IOCs do mesmo adversário através
  de campanhas distintas.
- **Comunidades (Louvain):** clusters de campanha/infraestrutura que **nenhum
  sinal isolado evidencia** — revelados pela sobreposição de hubs.
- Frontend: IOCs **coloridos por comunidade** (preenchimento) com a **severidade
  na borda**; legenda e filtros atualizados.
- Tecnologia: `networkx` + `python-louvain`, com degradação graciosa.

### P4 — Admiralty Code (padrão NATO 6×6)
Adota a notação de inteligência **NATO/SANS** que avalia **dois eixos separados**:

- **Confiabilidade da FONTE** (letra A–F): de "completamente confiável" a "sem
  histórico" (derivada do componente S).
- **Credibilidade da INFORMAÇÃO** (número 1–6): de "confirmado por múltiplas
  fontes" a "não avaliável" (derivada da corroboração por famílias).

Resultado: um grade legível como **`B2`**, exibido no drawer com explicação. Não
altera o score — é uma **leitura padrão de SOC** da confiança, com os eixos
avaliados sem que um enviese o outro.

---

## 10. Orquestração via Apache Airflow

- DAG `aegis_pipeline_dag.py` agendado diariamente às **08:00 UTC**.
- Modelo correto para produção: o DAG **dispara a produção via HTTP**
  (`POST /api/pipeline/run`) e acompanha pelo `/health` — não escreve no banco
  local.
- **Segurança:** a chave de API é lida em runtime de uma Airflow Variable
  (`aegis_api_key`) ou env — **nunca hardcoded**.

---

## 11. API (principais endpoints)

| Endpoint | Função |
|---|---|
| `GET /` · `GET /report` | Dashboard / relatório |
| `GET /health` | Saúde + estatísticas de decay |
| `GET /api/iocs` | Listagem paginada e filtrável |
| `GET /api/stats` · `/api/stats/trends` | Estatísticas e tendências |
| `GET /api/overview` | Painel de panorama |
| `GET /api/graph` | Grafo de correlação (filtros: campanha, ator, ASN, país, seed) |
| `GET /api/lookup/{value}` | Consulta + enriquecimento ao vivo |
| `GET /api/iocs/{value}/context` | Contexto completo do IOC (drawer) |
| `GET /api/iocs/{value}/score-breakdown` | Explicação do score |
| `GET /api/iocs/{value}/campaign` | Contexto de campanha |
| `POST /api/iocs/{value}/false-positive` | Marcar/reverter FP |
| `POST /api/workbench/share` · `GET /api/workbench/{key}` | Workbench compartilhável |
| `POST /api/pipeline/run` | Dispara o pipeline (protegido) |

---

## 12. Qualidade, Segurança e Operação

- **Migrações aditivas e compatíveis:** colunas novas via `ADD COLUMN`, sem
  alterar dados existentes; tabelas novas via ORM (`create_all`).
- **Validação local:** todas as mudanças testadas em `.venv` + SQLite, com
  backups por etapa — **a produção não é tocada** durante o desenvolvimento.
- **Sem segredos versionados:** chaves vêm de variáveis de ambiente.
- **Degradação graciosa:** componentes opcionais (GeoIP2, GreyNoise,
  MalwareBazaar, warninglists, libs de grafo) são pulados sem quebrar o pipeline
  quando ausentes.

### Ações operacionais recomendadas
- Configurar `MALWAREBAZAAR_API_KEY` (ou `ABUSE_CH_API_KEY`) no ambiente para o
  contexto de malware das hashes.
- Rodar `refresh_warninglists` periodicamente (pode entrar no DAG) para manter as
  listas de infraestrutura legítima atualizadas.

---

## 13. Roadmap (frentes futuras)

- **Confiabilidade de fonte EMPÍRICA:** derivar o **S** do histórico real de
  falso-positivo por fonte (a tabela de sightings — P1 — já fundou os dados),
  substituindo os valores fixos.
- **WHOIS/RDAP:** idade do domínio como sinal de risco.
- **Passive DNS:** ligações histórico domínio↔IP.
- **Spamhaus DROP/EDROP:** netblocks bulletproof (ground-truth por ASN).
- **resolves-to no grafo:** ligar IP↔domínio via hostnames do Shodan.

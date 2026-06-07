<p align="center">
  <img src="screenshots/gif.gif" alt="AEGIS Threat Intelligence" width="692">
</p>

# AEGIS Threat Intelligence

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Live](https://img.shields.io/badge/demo-aegiscti.me-success)](https://aegiscti.me)

> Plataforma open source de Cyber Threat Intelligence (CTI) com pipeline automatizado, scoring auditável e Kill Chain reconstruída por atacante — acessível via browser, sem instalação.

**🌐 Acesse ao vivo:** [aegiscti.me](https://aegiscti.me)

---

## O que é o AEGIS?

O AEGIS é uma plataforma de inteligência de ameaças cibernéticas construída do zero por um único desenvolvedor. Ele coleta, normaliza, enriquece e correlaciona IOCs (Indicators of Compromise) de múltiplas fontes públicas em tempo real, entregando contexto acionável para analistas SOC — sem depender de ferramentas pagas.

O diferencial não é apenas agregar feeds: é transformar dados brutos em **inteligência interpretável**, com scoring auditável, decay automático por tipo de IOC, Kill Chain reconstruída por atacante e handoff de turno entre analistas.

---

## Instalação / Rodar Localmente

Requer **Python 3.11+** e **PostgreSQL**.

> ⚠️ **Projeto de portfólio em produção.** A instância oficial roda no Render com PostgreSQL e chaves de API privadas. Para subir uma instância própria você precisa configurar `DATABASE_URL` (PostgreSQL) e suas próprias chaves de API no `.env` (use o `.env.example` como referência). Sem essas credenciais a aplicação não sobe.

```bash
# 1. Clonar
git clone https://github.com/mateusdias96cs/aegis-threat-intelligence.git
cd aegis-threat-intelligence

# 2. Ambiente virtual
python3.11 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Dependências
pip install -r requirements.txt

# 4. Configurar variáveis de ambiente
cp .env.example .env             # edite com DATABASE_URL e suas chaves (ver tabela abaixo)

# 5. Rodar a API / dashboard
uvicorn src.api:app --reload     # http://localhost:8000

# 6. (Opcional) Rodar o pipeline de coleta uma vez
python -m src.main
```

---

## Variáveis de Ambiente

Copie `.env.example` para `.env` e preencha. As chaves de API públicas têm tier gratuito.

| Variável | Obrigatória | Descrição |
|---|---|---|
| `DATABASE_URL` | **Sim** | Conexão PostgreSQL. |
| `AEGIS_API_KEY` | **Sim** | Chave admin para endpoints protegidos (ex.: marcar falso-positivo). |
| `AEGIS_PUBLIC_KEY` | **Sim** | Chave read-only injetada no dashboard. |
| `AEGIS_BASE_URL` | Não | URL base da API publicada. |
| `OTX_API_KEY` | Não | AlienVault OTX (coletor). |
| `THREATFOX_API_KEY` | Não | abuse.ch ThreatFox (coletor). |
| `ABUSE_CH_API_KEY` | Não | Auth-Key abuse.ch (enricher MalwareBazaar). |
| `MALWAREBAZAAR_API_KEY` | Não | MalwareBazaar (família de malware por hash). |
| `GREYNOISE_API_KEY` | Não | GreyNoise (scanners de internet). |
| `CIRCL_USERNAME` / `CIRCL_PASSWORD` | Não | CIRCL Passive DNS + SSL (HTTP Basic Auth). |
| `CIRCL_MAX_LOOKUPS` | Não | Teto de consultas CIRCL por execução (default 100). |
| `MAXMIND_LICENSE_KEY` | Não | Baixa GeoLite2 (.mmdb) automaticamente em runtime. |
| `MAXMIND_DB_PATH` / `MAXMIND_ASN_DB_PATH` / `GEOIP_DATA_DIR` | Não | Paths GeoLite2 (auto-resolvidos por glob). |
| `SENTRY_DSN` | Não | Monitoramento de erros (Sentry). |
| `DOPPLER_ENVIRONMENT` / `ENVIRONMENT` | Não | Tag de ambiente (default `production`). |
| `PIPELINE_MIN_INTERVAL_MIN` | Não | Intervalo mínimo entre runs do pipeline (default 15 min). |

---

## Funcionalidades

### IOC Dashboard
Visão consolidada de todos os indicadores ativos com filtros por severidade, tipo, status e busca full-text. Suporte a exportação em CSV compatível com SIEMs (Splunk, QRadar, Microsoft Sentinel).

![Dashboard](screenshots/dashboard.png)

### Threat Profiling por Asset
O analista cadastra as tecnologias do ambiente que está defendendo — Apache, MySQL, AWS, Active Directory, etc. O sistema filtra automaticamente os IOCs relevantes para aquele stack específico, separando o que é ruído do que é ameaça real.

![Threat Profiling](screenshots/threat-profiling.png)

Nenhuma ferramenta CTI gratuita do mercado faz isso.

### Campaigns — Attacker Behaviour Profile
Ao abrir qualquer IOC e clicar em **Ver Kill Chain**, o sistema reconstrói o comportamento completo do atacante com base em dados reais reportados por analistas no AbuseIPDB, mapeados para o framework MITRE ATT&CK.

![Kill Chain](screenshots/killchain.png)

Em vez de ver "score 100", o analista vê:
```
Reconnaissance → Initial Access → Credential Access → Lateral Movement
Port Scan         Hacking           Brute Force         SSH Attack
T1046             —                 T1110               T1021.004
```

Com correlação de IPs que apresentaram o mesmo padrão de ataque na mesma janela temporal.

### MITRE ATT&CK Explorer
Navegação completa pelas técnicas do framework MITRE ATT&CK carregadas automaticamente pelo pipeline, com filtro por tática e busca por ID ou nome.

![MITRE Explorer](screenshots/mitre-explorer.png)

### Analyst Workbench
Área de investigação local por analista — pina IOCs suspeitos, escreve notas de contexto e gera um código de compartilhamento para handoff de turno. O próximo analista cola o código e vê os IOCs e anotações em modo leitura.

![Workbench](screenshots/workbench.png)

Resolve o problema de handoff entre turnos em SOCs 24/7 sem depender de e-mail ou planilha.

### Threat Overview & Correlation Graph
Painel de panorama com KPIs e rankings clicáveis (campanhas, adversários, ASNs e países) e um grafo navegável de correlação entre IOCs. As arestas representam infraestrutura comum do atacante — campanha compartilhada, mesmo adversário, mesmo ASN e sub-rede /24 — e a **detecção de comunidades (Louvain)** revela clusters de infraestrutura mesmo quando os indicadores não compartilham um identificador explícito.

### Confiabilidade e Qualidade dos Dados
Camada dedicada a elevar a confiança dos indicadores:
- **Proveniência por fonte** — linhagem de coleta: qual fonte viu cada IOC, quando e quantas vezes.
- **Redução de falso-positivo** — IOCs que casam infraestrutura legítima conhecida (faixas de cloud/CDN, DNS público e domínios populares via Tranco) são sinalizados e têm o score rebaixado, sem serem descartados.
- **Admiralty Code (NATO 6×6)** — notação padrão de SOC que avalia a confiabilidade da fonte (A–F) e a credibilidade da informação (1–6) em eixos separados.
- **Completude de contexto** — métrica que indica quantas dimensões de contexto cada IOC tem preenchidas.

---

## Fontes de Dados

| Fonte | Tipo | Volume |
|---|---|---|
| CISA KEV | CVEs explorados ativamente | ~75 recentes |
| AlienVault OTX | IPs, domínios, hashes, URLs | ~300 por run |
| ThreatFox | Malware e C2 | variável |
| URLhaus | URLs maliciosas | até 2.000 |
| Feodo Tracker | IPs de botnet C2 | ~5 |
| DShield / SANS ISC | IPs atacantes (telemetria de firewall) | ~500 por run |
| Emerging Threats | IPs maliciosos | variável |
| GreyNoise | Scanners de internet | variável |
| IPsum | IPs maliciosos agregados (multi-blocklist) | variável |
| Spamhaus DROP | Faixas/IPs hijacked e maliciosos | variável |

**Enriquecimento:** os IOCs são enriquecidos com GeoIP2/ASN (MaxMind), Shodan InternetDB (portas, serviços e vulnerabilidades por IP), EPSS/FIRST.org (probabilidade de exploração de CVE), MalwareBazaar (família de malware por hash), RDAP (idade do registro do domínio) e **CIRCL Passive DNS + Passive SSL**.

**CIRCL Passive DNS** mantém o histórico real de resoluções DNS: para um domínio, quais IPs ele já apontou; para um IP, quais domínios já hospedou — com primeira/última observação e contagem. Permite pivotar por infraestrutura e expõe sinais de bullet-proof hosting / fast-flux.

**CIRCL Passive SSL** mantém o histórico de certificados X.509 vistos por IP, permitindo rastrear a infraestrutura do atacante por fingerprint de certificado mesmo quando ele troca de domínio.

Os sinais de pDNS/pSSL (idade do histórico de DNS, fast-flux, certificado auto-assinado, validade anômala, CA emissora) alimentam uma **avaliação de legitimidade da infraestrutura** — um veredito de contexto (*legítimo / suspeito / misto*) que ajuda o analista a separar infraestrutura legítima de descartável. É uma dimensão de **contexto**, exposta no drawer e contabilizada na completude de contexto — **não altera o score de confiança**.

> _Access requires registration with CIRCL (circl.lu) — trusted partner network._ Configure as variáveis de ambiente `CIRCL_USERNAME` e `CIRCL_PASSWORD` (HTTP Basic Auth) no Render para ativar; sem elas o pipeline segue sem os dados de pDNS/pSSL. O teto de consultas por execução é controlado por `CIRCL_MAX_LOOKUPS` (fair use: chamadas sequenciais, 1 req/s).

**Total atual no banco: mais de 39.000 IOCs ativos**

---

## Scoring — BioSec Framework

Cada IOC recebe um score auditável calculado por três componentes:

```
Score = (S × 0.40) + (C × 0.30) + (T × 0.30)
```

| Componente | Descrição |
|---|---|
| **S** — Source Reliability | Confiabilidade da fonte (CISA=100, Feodo=85, ThreatFox=80...) |
| **C** — Corroboration | Quantas famílias de fontes independentes confirmaram o IOC (feeds da mesma organização não somam) |
| **T** — Type Severity | Para CVEs: CVSS da NVD ou probabilidade de exploração (EPSS). Para IPs: score de abuso/ataque |

O breakdown completo é auditável por IOC no drawer, com links para as fontes de referência.

### Decay Automático
IOCs perdem relevância com o tempo de forma diferenciada por tipo:

| Tipo | Meia-vida |
|---|---|
| URL | 7 dias |
| IP | 15 dias |
| Domínio | 30 dias |
| Hash | 180 dias |
| CVE | 365 dias |

Equação: `score_atual = score_original × e^(−0.693 × dias / meia_vida)`

---

## Stack Técnica

| Camada | Tecnologia |
|---|---|
| Backend | Python 3.11 + FastAPI |
| Banco de dados | PostgreSQL (Render) |
| ORM | SQLAlchemy 2.0 |
| Orquestração | Apache Airflow (pipeline diário 08:00 UTC) |
| Deploy | Render (web service + PostgreSQL) |
| Monitoramento | Sentry |
| Template engine | Jinja2 |
| Integração SIEM | TAXII 2.1 / STIX 2.1 |

---

## API

A plataforma expõe uma API REST documentada com autenticação por API Key:

```bash
# Lookup de um IOC
GET /api/lookup/{value}

# IOCs paginados com filtros
GET /api/iocs?page=1&severity=CRITICAL&type=ip

# Contexto completo de um IOC
GET /api/iocs/{value}/context

# Kill Chain e correlações
GET /api/iocs/{value}/campaign

# Estatísticas da plataforma
GET /api/stats

# Feed TAXII 2.1 compatível com Splunk/QRadar
GET /taxii/collections/critical/objects/

# Exportação em batch (até 10 IOCs)
POST /api/lookup/batch
```

---

## Integrações SIEM

O AEGIS exporta IOCs em dois formatos:

**CSV SIEM** — exportação selecionada diretamente pelo dashboard com campos:
`indicator_type, indicator_value, severity, confidence_score, ioc_status, source, country_code, mitre_tactic, mitre_technique_id, mitre_technique_name, cvss_score, first_seen, last_seen`

**TAXII 2.1 / STIX 2.1** — feed compatível com Splunk, QRadar e Microsoft Sentinel via endpoint `/taxii/`. IDs determinísticos via UUID5 — o mesmo IOC sempre gera o mesmo STIX ID.

---

## Estrutura do Projeto

```
aegis-threat-intelligence/
├── src/
│   ├── collectors/      # CISA, OTX, MITRE, ThreatFox, URLhaus, Feodo, DShield, EmergingThreats, GreyNoise, IPsum, Spamhaus
│   ├── enrichers/       # GeoIP2/ASN, Shodan, EPSS, MalwareBazaar, RDAP, CIRCL pDNS/pSSL
│   ├── processors/      # Normalizer, Classifier, Deduplicator, Warninglist
│   ├── storage/         # DatabaseManager, MITRE cache
│   ├── reporters/       # Gerador de relatório HTML
│   ├── scripts/         # Backfills e enriquecimentos pontuais
│   ├── api.py           # FastAPI — 15+ endpoints
│   └── main.py          # Orquestração do pipeline
├── dags/                # DAG do Airflow (pipeline diário 08:00 UTC)
├── tests/               # Smoke tests + testes do normalizer
├── data/warninglists/   # Faixas cloud/CDN, DNS público, Tranco (redução de FP)
├── templates/report.html # Dashboard SPA (6 abas)
├── assets/              # Logo, favicons
├── screenshots/         # Imagens do README
├── migrate_circl.py     # Migração standalone das colunas CIRCL
├── Dockerfile
├── render.yaml          # Blueprint Render (web + cron pipeline)
└── requirements.txt
```

---

## Sobre o Projeto

Desenvolvido de forma independente com foco em resolver lacunas documentadas em ferramentas CTI gratuitas disponíveis no mercado, voltado a SOC N1 / Blue Team e DevSecOps.

O AEGIS resolve problemas reais documentados no **SANS 2025 CTI Survey**:
- 62% da inteligência coletada não se torna acionável
- Ausência de decay automático em feeds CTI
- Falta de contexto tático para analistas N1
- Sem mecanismo de handoff entre turnos de SOC

## Licença

Distribuído sob a licença **MIT**. Veja [`LICENSE`](LICENSE) para detalhes.

**GitHub:** [github.com/mateusdias96cs/aegis-threat-intelligence](https://github.com/mateusdias96cs/aegis-threat-intelligence)
**Demo:** [aegiscti.me](https://aegiscti.me)

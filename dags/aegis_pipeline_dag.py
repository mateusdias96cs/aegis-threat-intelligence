"""
DAG de orquestração do pipeline AEGIS Threat Intelligence.

Este DAG vive no repositório do projeto (versionado), mas o Airflow roda em um
ambiente SEPARADO. Para usá-lo, aponte o `dags_folder` do seu Airflow para esta
pasta:

    # airflow.cfg
    dags_folder = /caminho/para/aegis-threat-intelligence/dags

Modelo de execução: o pipeline roda NA PRODUÇÃO (Render), disparado por HTTP via
`POST /api/pipeline/run`. O Airflow apenas orquestra o gatilho diário e acompanha
a conclusão pelo `/health`. (Rodar localmente escreveria no SQLite local, não no
Postgres de produção — por isso o gatilho é remoto.)

Configuração obrigatória (NUNCA hardcode a chave):
    airflow variables set aegis_api_key   "<sua AEGIS_API_KEY>"
    # opcional (default https://aegiscti.me):
    airflow variables set aegis_base_url  "https://aegiscti.me"
Alternativa: variáveis de ambiente AEGIS_API_KEY / AEGIS_BASE_URL.
"""

import os
import time
from datetime import datetime, timedelta, date

import requests
from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator

default_args = {
    "owner": "aegis",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
    "email_on_failure": False,
    "execution_timeout": timedelta(hours=2),
}


def _base_url() -> str:
    """Resolve a URL base em runtime (Airflow Variable > env > default)."""
    try:
        return Variable.get("aegis_base_url")
    except Exception:
        return os.getenv("AEGIS_BASE_URL", "https://aegiscti.me")


def _api_key() -> str:
    """Resolve a chave de API em runtime — Airflow Variable > env. Nunca hardcoded."""
    try:
        return Variable.get("aegis_api_key")
    except Exception:
        key = os.getenv("AEGIS_API_KEY")
        if not key:
            raise RuntimeError(
                "Defina a Airflow Variable 'aegis_api_key' ou a env AEGIS_API_KEY "
                "(a chave NÃO deve ser escrita no DAG)."
            )
        return key


def _get_json(url: str, timeout: int = 10, attempts: int = 3):
    """GET + parse JSON tolerante a corpo vazio/instável (API reiniciando no Render).

    Durante um restart do Render o /health pode devolver corpo vazio ou 5xx, e
    `resp.json()` direto estoura JSONDecodeError, derrubando a task. Aqui re-tenta
    `attempts` vezes com 15s de espera e só então lança um erro CLARO. Não devolve
    baseline inválido (defaultar total_before=0 faria o wait declarar conclusão na
    primeira leitura)."""
    last = None
    for i in range(1, attempts + 1):
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            last = e
            if i < attempts:
                print(f"GET {url} falhou ({e}) — aguardando 15s e re-tentando ({i}/{attempts}) ...")
                time.sleep(15)
    raise Exception(f"Não foi possível obter JSON de {url} após {attempts} tentativa(s): {last}")


def check_aegis_health():
    data = _get_json(f"{_base_url()}/health", timeout=10, attempts=3)
    print(f"Total IOCs: {data['database']['total_iocs']}")
    print(f"Status: {data['status']}")
    return data


def trigger_aegis_pipeline(**context):
    """Dispara o pipeline (POST único) e devolve o total_iocs ANTES via XCom.

    Tarefa SEPARADA da espera e com `retries: 0` (ver task_kwargs): se a espera
    falhar e o Airflow re-tentar, é só a ESPERA que repete — o gatilho NUNCA é
    re-disparado. Isso elimina o run duplicado (10:13 e 10:32) causado pelo retry
    da tarefa monolítica antiga re-POSTando /api/pipeline/run."""
    base = _base_url()
    health_before = _get_json(f"{base}/health", timeout=10, attempts=3)
    total_before = health_before.get("database", {}).get("total_iocs", 0)
    timestamp_before = health_before.get("database", {}).get("last_updated", "")
    print(f"Antes: total_iocs={total_before}, last_updated={timestamp_before}")

    # POST com retry/backoff: durante restart do Render a API pode devolver corpo
    # vazio ou 5xx — nesses casos o pipeline provavelmente NEM iniciou, então re-tentar
    # é seguro (o guard de idempotência server-side barra disparo duplicado). 4xx é
    # erro definitivo (chave/rota) — falha na hora, sem re-tentar.
    last_err = None
    for attempt in range(1, 4):  # até 3 tentativas
        response = requests.post(
            f"{base}/api/pipeline/run", timeout=30, headers={"X-API-Key": _api_key()}
        )
        try:
            body = response.json()
        except Exception:
            body = response.text or "(resposta vazia)"
        print(f"Pipeline iniciado (tentativa {attempt}/3): {body}")

        if 400 <= response.status_code < 500:
            raise Exception(f"API retornou erro {response.status_code}: {body}")

        empty = not (response.text or "").strip()
        if response.status_code >= 500 or empty:
            last_err = f"status {response.status_code}, corpo: {body}"
            if attempt < 3:
                print(f"API instável ({last_err}) — aguardando 15s e re-tentando ...")
                time.sleep(15)
                continue
            raise Exception(f"API falhou após 3 tentativas: {last_err}")
        break  # 2xx/3xx com corpo — sucesso

    return total_before


def wait_for_aegis_pipeline(**context):
    """Acompanha a conclusão pelo /health. Idempotente — seguro re-tentar."""
    base = _base_url()
    total_before = context["ti"].xcom_pull(task_ids="trigger_pipeline") or 0
    print(f"Aguardando pipeline terminar (baseline total_iocs={total_before})...")
    time.sleep(30)  # espera inicial — pipeline leva ~3 min

    today = str(date.today())
    for i in range(120):  # até ~90 min no total (30s + 120×45s)
        time.sleep(45)
        try:
            health = requests.get(f"{base}/health", timeout=15).json()
        except Exception as e:
            print(f"Tentativa {i+1}: erro ao consultar health ({e}), continuando...")
            continue

        db = health.get("database", {})
        total_now = db.get("total_iocs", 0)
        last = db.get("last_updated", "")
        print(f"Tentativa {i+1}: total_iocs={total_now}, last_updated={last}")

        if total_now > total_before:
            print(f"Pipeline concluído! IOCs: {total_before} → {total_now}")
            return health
        if i >= 4 and last == today and total_now != total_before:
            print(f"Pipeline concluído por tempo (last_updated={last}, iocs={total_now})")
            return health

    raise Exception("Pipeline não concluiu em 90 minutos")


with DAG(
    dag_id="aegis_threat_intelligence_pipeline",
    default_args=default_args,
    description="Pipeline diário de coleta de IOCs do AEGIS CTI",
    schedule_interval="0 8 * * *",  # diário, 08:00 UTC
    start_date=datetime(2026, 1, 1),
    catchup=False,
    max_active_runs=1,
    tags=["aegis", "security", "cti"],
) as dag:

    health_check = PythonOperator(
        task_id="health_check",
        python_callable=check_aegis_health,
    )

    # O gatilho NÃO re-tenta: um retry aqui significaria disparar o pipeline duas
    # vezes. A idempotência server-side (PIPELINE_MIN_INTERVAL_MIN) é a segunda
    # rede de proteção caso outro gatilho (GitHub Actions) colida no mesmo horário.
    trigger_pipeline = PythonOperator(
        task_id="trigger_pipeline",
        python_callable=trigger_aegis_pipeline,
        retries=0,
    )

    # Só a espera é re-tentável (polling é idempotente, não re-dispara nada).
    wait_pipeline = PythonOperator(
        task_id="wait_pipeline",
        python_callable=wait_for_aegis_pipeline,
    )

    health_check >> trigger_pipeline >> wait_pipeline

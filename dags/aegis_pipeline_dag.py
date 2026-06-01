"""
DAG de orquestração do pipeline AEGIS Threat Intelligence.

Este DAG vive no repositório do projeto (versionado), mas o Airflow roda em um
ambiente SEPARADO. Para usá-lo, basta apontar o `dags_folder` do seu Airflow
para esta pasta:

    # airflow.cfg
    dags_folder = /caminho/para/aegis-threat-intelligence/dags

O pipeline NÃO compartilha o ambiente Python do Airflow — ele é executado pelo
`.venv` próprio do projeto (o único com geoip2/sqlalchemy 2.0). Isso evita o
conflito de dependências entre o Airflow e o AEGIS (ex.: versão do SQLAlchemy).
"""

from datetime import datetime, timedelta
from pathlib import Path

from airflow import DAG
from airflow.operators.bash import BashOperator

# O DAG está dentro do repo (dags/), então o diretório do projeto é o pai desta
# pasta — descoberto dinamicamente, sem caminho hardcoded.
PROJECT_DIR = Path(__file__).resolve().parent.parent
VENV_PYTHON = PROJECT_DIR / ".venv" / "bin" / "python"

default_args = {
    "owner": "aegis",
    "retries": 1,
    "retry_delay": timedelta(minutes=10),
    "execution_timeout": timedelta(minutes=30),
}

with DAG(
    dag_id="aegis_ioc_pipeline",
    description="Coleta, enriquece, correlaciona e pontua IOCs (AEGIS CTI)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="0 8 * * *",  # diário, 08:00 UTC
    catchup=False,
    max_active_runs=1,
    tags=["aegis", "cti", "iocs"],
) as dag:

    run_pipeline = BashOperator(
        task_id="run_aegis_pipeline",
        # Roda no venv do projeto, a partir da raiz do repo (imports de src.* ok).
        bash_command=(
            f"cd {PROJECT_DIR} && "
            f"{VENV_PYTHON} -m src.main"
        ),
    )

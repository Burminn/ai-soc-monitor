FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SOC_DB_PATH=/data/soc.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Użytkownik bez uprawnień; baza w woluminie /data.
RUN useradd --system --uid 10001 --no-create-home soc && mkdir -p /data && chown soc /data
USER soc
VOLUME /data

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','5000')+'/healthz',timeout=2)" || exit 1

# Jeden worker: oczekujące importy (podgląd -> zatwierdzenie) są w pamięci procesu.
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:5000", "bi_server:app"]

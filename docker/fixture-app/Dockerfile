# fixture-app: small deliberately-vulnerable Flask API used only to prove out
# the BOLA/privilege-escalation/SQLi DAST modules end-to-end. Never expose
# this outside an isolated local Docker network.
FROM python:3.12-slim

WORKDIR /app
RUN useradd -m fixture && mkdir -p /data && chown fixture:fixture /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER fixture

EXPOSE 5001
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "app:app"]

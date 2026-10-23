FROM python:3.12-slim

WORKDIR /app

ENV PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY security ./security
COPY dashboard ./dashboard
COPY .streamlit/config.toml ./.streamlit/config.toml
COPY datasets ./datasets
COPY tests ./tests

EXPOSE 8000 8501

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

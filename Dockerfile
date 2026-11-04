FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 8541
LABEL org.opencontainers.image.source="https://github.com/stewcloud/CoffeePOS" \
      org.opencontainers.image.description="Self-hosted coffee ordering and printing system" \
      org.opencontainers.image.licenses="MIT"
CMD ["waitress-serve", "--listen=0.0.0.0:8541", "app:app"]

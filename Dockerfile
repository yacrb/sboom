FROM anchore/syft:v1.55.0 AS scanner
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY --from=scanner /syft /usr/local/bin/syft
WORKDIR /opt/sboom
COPY . .
RUN pip install --no-cache-dir . && useradd --create-home sboom
USER sboom
ENV SBOOM_CONTAINER=1
EXPOSE 8765
ENTRYPOINT ["sboom"]
CMD ["dashboard"]

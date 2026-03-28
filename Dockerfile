FROM python:3.12-slim-bookworm

WORKDIR /app

# Install git + gitleaks
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates curl \
    && GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
       | tar xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "scan.py"]
CMD ["--all"]

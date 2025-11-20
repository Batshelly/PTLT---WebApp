FROM python:3.11

# Install system dependencies including LibreOffice and all packages from nixpacks
RUN apt-get update && apt-get install -y \
    libreoffice \
    libreoffice-writer \
    default-libmysqlclient-dev \
    build-essential \
    pkg-config \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

EXPOSE 8080

CMD gunicorn PTLT.wsgi --bind 0.0.0.0:$PORT --log-file -

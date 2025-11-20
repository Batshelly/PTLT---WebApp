FROM python:3.11

# Install system dependencies including LibreOffice
RUN apt-get update && apt-get install -y \
    libreoffice \
    libreoffice-writer \
    default-libmysqlclient-dev \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Expose port (Railway uses $PORT)
EXPOSE 8080

# Run gunicorn
CMD gunicorn PTLT.wsgi --bind 0.0.0.0:$PORT --log-file -

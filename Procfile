release: python manage.py migrate && python manage.py collectstatic --no-input
web: gunicorn PTLT.wsgi --bind 0.0.0.0:$PORT --log-file -

# AICyberChain

AICyberChain is a Django-based cyber threat monitoring project that combines traffic analysis, machine learning, live monitoring, IP blocking, and optional blockchain logging for security events.

## Features

- Manual traffic-log analysis through the web dashboard
- CSV upload analysis for batch traffic inspection
- Live packet monitoring with suspicious activity detection
- Threat history and dashboard visualizations
- IP blocking through Django middleware
- Optional Ganache/Web3 smart-contract logging for tamper-resistant records

## Project Structure

- `cybersec_webapp/` Django application
- `cybersec_webapp/threat_app/` threat detection, dashboard, ML integration, middleware, blockchain logic
- `code/` training scripts, data generation, packet capture, preprocessing, and experiments

## Tech Stack

- Python
- Django
- pandas
- scikit-learn
- joblib
- scapy
- Web3.py
- py-solc-x

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set environment variables from `.env.example`.
4. Run migrations:

```bash
python manage.py migrate
```

5. Start the server from `cybersec_webapp/`:

```bash
python manage.py runserver
```

## Environment Variables

- `DJANGO_SECRET_KEY`
- `DJANGO_DEBUG`
- `DJANGO_ALLOWED_HOSTS`
- `EMAIL_HOST_USER`
- `EMAIL_HOST_PASSWORD`

## Notes

- This repository is intended for academic/demo use.
- Generated datasets, captures, SQLite databases, caches, and trained artifacts should usually not be committed.
- If blockchain logging is used, start Ganache locally before using the relevant features.

## Suggested Repository Description

AI-powered cyber threat monitoring system built with Django, machine learning, live packet analysis, and blockchain-based threat logging.

FROM python:3.11.9-slim

WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
EXPOSE 5000

ENV FLASK_APP=run.py
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
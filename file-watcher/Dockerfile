FROM python:3

COPY ./requirements.txt /
RUN pip install -r requirements.txt
RUN mkdir /run/secrets/

COPY ./watcher.py /
ENTRYPOINT ["python", "./watcher.py"]

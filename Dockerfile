FROM python:3-slim
LABEL maintainer "Peter Benjamin <petermbenjamin@gmail.com>"
WORKDIR /src/vtapi
COPY . .
RUN pip install -r requirements.txt
ENTRYPOINT [ "python", "vt/vt3.py" ]

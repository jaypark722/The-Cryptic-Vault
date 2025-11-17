FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
    gnupg \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
# Ensure the database directory exists in the image and is writable.
# We make it world-writable so that when a host directory is bind-mounted
# the SQLite files can be created and written by the container user.
# If you prefer a stricter setup, create a host directory and set its
# owner UID/GID to match the container user (see README for details).
RUN mkdir -p /app/database && chmod 0777 /app/database

# Ensure SSH runtime directory exists for SSH server (if used in container)
RUN mkdir -p /var/run/sshd

# Declare the database folder as a mountable volume so Docker knows this
# path is expected to be persistent. The actual persistence is provided
# by a bind mount or a named volume on the host (see docker-compose.yml
# or the provided `docker run` example in the README).
VOLUME ["/app/database"]

ENV FLASK_APP=app.py
EXPOSE 5000
EXPOSE 2222
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
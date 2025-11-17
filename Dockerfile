# Use a slim Python image for the web application
FROM python:3.12-slim

# Set working directory
WORKDIR /usr/src/app

# Install system dependencies (gnupg for encryption features)
RUN apt-get update && apt-get install -y \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create database directory
RUN mkdir -p /usr/src/app/database

# Expose the port for the web application
EXPOSE 5000

# Run the database initialization and then the application
CMD ["sh", "-c", "python init_db.py && python app.py"]
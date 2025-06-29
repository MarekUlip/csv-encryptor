FROM python:3.13-slim

# Install dependencies
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend and frontend
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Expose Flask on port 5000
ENV FLASK_APP=backend/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

# Add CORS headers and static serving via Flask
RUN pip install flask-cors

# Start the app
CMD ["flask", "run"]

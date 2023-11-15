# Use an official Python runtime as a parent image
FROM python:3.12-rc-slim-bullseye

# Install any needed packages specified in requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get install -y libffi-dev gcc npm curl git
WORKDIR /app
COPY . /app
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Build Obfuscator
WORKDIR /app/obfuscator
RUN git clone https://github.com/MrDomainAdmin/javascript-obfuscator 
RUN npm install -g n
RUN apt-get install -y curl
RUN n 18.18.2
RUN npm install -g npm@latest
RUN npm install -g pkg yarn
WORKDIR /app/obfuscator/javascript-obfuscator
RUN npm install
RUN npm run build && npm run build:typings
RUN pkg . --output /app/javascript-obfuscator --targets node18-linux-x64
WORKDIR /app

# Expose ports
EXPOSE 8080
EXPOSE 443

# Run app.py when the container launches
CMD ["python", "teamserver.py", "--ip", "0.0.0.0", "--port", "443", "--apiport", "8080", "--obfuscate"]

FROM node:18.18.2-bookworm
WORKDIR /app
RUN git clone https://github.com/MrDomainAdmin/javascript-obfuscator
RUN npm install -g pkg
WORKDIR /app/javascript-obfuscator
RUN npm install
RUN npm run build && npm run build:typings
RUN mkdir /obfuscators

#CMD ["pkg", ".", "--output", "/obfuscators/javascript-obfuscator", "--targets", "node18-linux-x64,node18-macos-x64,node18-win-x64"]
CMD echo "building ..." && pkg . --output /obfuscators/javascript-obfuscator --targets node18-linux-x64,node18-macos-x64,node18-win-x64 > /dev/null && echo "Obfuscator executables are in the output directory."

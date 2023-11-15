from typing import List
from dbmgmt import InitDatabase, listDB, saveToDB
import time


agents = {}


class Agent:
    def __init__(
        self,
        agentid: str,
        uid: str,
        systemName: str,
        checkinTime: str,
        commandList: List[str],
    ):
        self.agentid = agentid
        self.uid = uid
        self.systemName = systemName
        self.checkinTime = checkinTime
        self.commandList = commandList


def resetAgents():
    print("Clearing all agent data from memory")

    try:
        agents.clear()
    except KeyError:
        pass


def updateAgent(agent):
    agents[agent.agentid] = agent
    return agents


def addCommand(agentid, command):
    agents[agentid].commandList.append(command)


def addCommands(agentid, commands):
    for command in commands:
        print(f"ADDING {command}")
        agents[agentid].commandList.append(command)
        time.sleep(1)


# Reads command list and clears the queue
def getCommand(agentid):
    commandlist = ""
    commands = agents[agentid].commandList
    for command in commands:
        commandlist = commandlist + "\n" + command
    agents[agentid].commandList = []
    return commandlist


# Reads command list without clearing queue
def readCommand(agentid):
    commandlist = ""
    commands = agents[agentid].commandList
    for command in commands:
        commandlist = commandlist + "\n" + command
    return commandlist


def clearCommands(agentid):
    agents[agentid].commandList = []


def listAgentMap():
    agentList = []
    for agent in agents:
        agentList.append(agent)
    return agentList


def listAgents():
    agentNames = []
    for agent in agents.values():
        agentNames.append(agent.agentid)
    return agentNames


def receiveTask(agentid):
    return agents[agentid].commandList


def getAgentMap():
    return agents


def getAgent(agentid):
    return agents[agentid]


def taskExists(agentid):
    if not len(agents[agentid].commandList) == 0:
        return True
    else:
        return False


def killAgent(agentid):
    try:
        while taskExists(agentid):
            time.sleep(1)
        print(f"Agent {agentid} is exiting.")
        del agents[agentid]
    except KeyError:
        pass


def removeAgent(agentid):
    try:
        del agents[agentid]
    except KeyError:
        pass


def convertDBCommandList(commands):
    commandList = commands.split("\n")
    return commandList


def loadFromDB():
    agentlist = []
    rows = listDB()
    if len(rows) == 0:
        print("Database empty. Creating new map.")
        return {}
    for row in rows:
        agentid = row[0]
        uid = row[1]
        systemName = row[2]
        checkinTime = row[3]
        if row[4] == "":
            commandList = []
        else:
            commandList = convertDBCommandList(row[4])
        agent = Agent(agentid, uid, systemName, checkinTime, commandList)
        agentlist.append(agent)
    agents = {agent.agentid: agent for agent in agentlist}

    return agents
    # In-Memory list of agents from DB


def agentsToDB():
    saveToDB(getAgentMap())
    return True


InitDatabase()
agents = loadFromDB()

import sqlite3


def InitDatabase():
    conn = sqlite3.connect("agents.db")
    c = conn.cursor()

    # Create the devices table
    c.execute(
        """CREATE TABLE IF NOT EXISTS agents
                 (agentid TEXT PRIMARY KEY,
                  uid TEXT,
                  systemName TEXT,
                  checkinTime TIMESTAMP,
                  commandList TEXT
                  )"""
    )

    # Save the changes
    conn.commit()

    # Close the cursor and the connection
    c.close()
    conn.close()


def listDB():
    conn = sqlite3.connect("agents.db")
    c = conn.cursor()
    c.execute("SELECT agentid, uid, systemName, checkinTime, commandList FROM agents")
    rows = c.fetchall()
    c.close()
    conn.close()
    return rows


def clearDB():
    conn = sqlite3.connect("agents.db")
    c = conn.cursor()
    c.execute("DELETE FROM agents")
    conn.commit()
    c.close()
    conn.close()


def saveToDB(agents):
    conn = sqlite3.connect("agents.db")
    c = conn.cursor()
    c.execute("DELETE FROM agents")
    conn.commit()
    for agent in agents.values():
        commands = commandToDB(agent.commandList)
        c.execute(
            "INSERT OR REPLACE INTO agents (agentid, uid, systemName, checkinTime, commandList) VALUES (?,?,?,?,?)",
            (agent.agentid, agent.uid, agent.systemName, agent.checkinTime, commands),
        )
        conn.commit()
    # Commit the transaction and close the connection
    c.close()
    conn.close()


def commandToDB(commandList):
    commands = ""
    for command in commandList:
        commands = commands + "\n" + command
    return commands


# def DBCheckIn(agentid, uid, compid, output, date):
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	#DBCheckIn(agentid,uid, compid, datetime.now(), output)
# 	c.execute("SELECT * FROM agents WHERE agentid=?", (agentid,))
# 	row = c.fetchone()
# 	if row is None:
# 		# New Beacon!
# 		compid = getsystemid(compid)
# 		print(f'New beacon {agentid}: {compid} has checked in!')
# 		printLog(f'New beacon {agentid}: {compid} has checked in!')
# 		commandList = None
# 		c.execute("INSERT INTO agents VALUES (?, ?, ?, ?, ?)", (agentid, uid, compid,date,commandList))
# 		c.close()
# 		conn.commit()
# 		return False
# 	else:
# 		if output is not None:
# 			print(f"New Output from {agentid}: \n{output.strip()}")
# 			printLog(f"New Output from {agentid}: \n{output.strip()}")
# 		c.execute("UPDATE agents SET checkinTime = ?  WHERE agentid = ?", (date, agentid))
#
# 		conn.commit()
# 		c.close()
# 		conn.close()
#
# 		if row[4] is not None:
# 			return True
# 		else:
# 			return False


# def checkExist(agentid):
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	c.execute("SELECT * FROM agents WHERE agentid=?", (agentid,))
# 	row = c.fetchone()
# 	c.close()
# 	conn.close()
# 	if row is not None:
# 		return True
# 	else:
# 		return False

# def sendTask(agentid, command):
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	c.execute("SELECT agentid, commandList FROM agents WHERE agentid = ?", (agentid,))
# 	row = c.fetchone()
# 	if row[1] is not None:
# 		command = row[1] + "\n" + command
# 	c.execute("UPDATE agents SET commandList = ? WHERE agentid = ?", (command ,agentid))
# 	conn.commit()
# 	c.execute("SELECT agentid, commandList FROM agents WHERE agentid = ?", (agentid,))
# 	row = c.fetchone()
# 	c.close()
# 	conn.close()
#
# def receiveTask(agentid):
# 	commands = "hi"
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	c.execute("SELECT commandList FROM agents WHERE agentid = ?", (agentid,))
# 	row = c.fetchone()
# 	if row[0] is not None:
# 		commands = row[0]
# 	c.execute("UPDATE agents SET commandList = ? WHERE agentid = ?", (None,agentid,))
# 	conn.commit()
# 	c.close()
# 	conn.close()
# 	if commands == "WScript.Quit()":
# 		print("Deleting Beacon!")
# 		removeAgent(agentid)
# 	return commands


# def listAgents():
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	#DBCheckIn(agentid,uid, compid, datetime.now(), output)
# 	c.execute("SELECT agentid FROM agents")
# 	rows = c.fetchall()
# 	c.close()
# 	conn.close()
# 	data = []
# 	for row in rows:
# 		data.append(row[0])
# 	return data

# def removeAgent(agentid):
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	c.execute("DELETE FROM agents WHERE agentid = ?", (agentid,))
# 	conn.commit()
# 	c.close()
# 	conn.close()
#
# def printDB():
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	#DBCheckIn(agentid,uid, compid, datetime.now(), output)
# 	c.execute("SELECT agentid, uid, systemName, checkinTime FROM agents")
# 	rows = c.fetchall()
# 	c.close()
# 	conn.close()
# 	return rows
#

#
# def clearDB():
# 	conn = sqlite3.connect('agents.db')
# 	c = conn.cursor()
# 	c.execute("DELETE FROM agents")
# 	conn.commit()
# 	c.close()
# 	conn.close()

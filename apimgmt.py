## NOT WORKING

from flask import Flask, request, make_response, render_template, jsonify
import threading
import time
import json


# import local files:
from util import *
from agent import *


# function to listen to incoming API requests
def apiListener(listenerIP, apiPort):
    # create an instance of Flask
    app = Flask("api")

    # Web interface
    @app.route("/", methods=["GET", "POST"])
    def webinterface():
        return render_template("homepage.html", agents=getAgentMap())

    @app.route("/agents")
    def getAgents():
        agentList = [agent.__dict__ for agent in agents.values()]
        return jsonify(agentList)

    @app.route("/interact/<string:agentid>")
    def interact(agentid):
        agents = getAgentMap()
        agent = agents[agentid]
        return render_template("interact.html", agent=agent)

    # API route to print database
    @app.route("/api/<path:path>", methods=["GET", "POST"])
    def general(path):
        if path == "printdb":
            # create an empty list to hold query results
            results = []
            # loop through each row in the database and add it to the results list
            for row in printDB():
                results.append(
                    {
                        "Agent ID": row[0],
                        "UID": row[1],
                        "Computer ID": row[2],
                        "Checkin Time": row[3],
                    }
                )
            # return the results as a JSON string
            return json.dumps(results)
        else:
            # return a simple string if the API route does not match the printdb route
            return ("meow", 200)

    # API route for running an agent
    @app.route("/api/agents/<agentid>/<run>")
    def agentRun(agentid, run):
        # print a simple message to indicate the function has been called
        print("We do everything here!")

    @app.route("/checkin_time/<agentid>")
    def checkinTime(agentid):
        agent = agents.get(agentid)
        if agent is not None:
            return jsonify({"checkin_time": agent.checkinTime})
        else:
            return jsonify({"error": "Agent not found"}), 404

    # start a new thread to run the Flask app
    threading.Thread(
        target=lambda: app.run(
            ssl_context=getContext(),
            host=listenerIP,
            port=apiPort,
            debug=True,
            use_reloader=False,
        )
    ).start()

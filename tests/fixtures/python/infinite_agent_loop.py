from google.adk.runners import Runner

def start_agent_runner(agent, session_id):
    # Missing max_iterations ceiling
    runner = Runner(agent=agent)
    return runner.run()

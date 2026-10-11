# Vulnerable: dynamic code execution on user-influenced input.
def run_user_code(user_input, cmd):
    result = eval(user_input)
    exec(cmd)
    return result

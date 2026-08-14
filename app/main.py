from engine import normalize_input, analyze, generate_output

user_input=input("Enter a security sceneario: ")

normalized = normalize_input(user_input)
analysis = analyze(normalized)

generate_output(user_input, analysis)
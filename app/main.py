from engine import analyze, generate_output, normalize_input

user_input = input("Enter a security scenario: ")

normalized = normalize_input(user_input)
analysis = analyze(normalized)

generate_output(user_input, analysis)

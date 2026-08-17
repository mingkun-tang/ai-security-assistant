from engine import analyze_scenario, render_structured_report

user_input = input("Enter a security scenario: ")

report = analyze_scenario(user_input)
render_structured_report(report)

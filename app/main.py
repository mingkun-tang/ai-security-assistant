from ai.explainer import explain_structured_result, render_ai_explanation
from ai.provider import get_provider
from engine import analyze_scenario, render_structured_report

user_input = input("Enter a security scenario: ")

report = analyze_scenario(user_input)
render_structured_report(report)

ai_explanation = explain_structured_result(report, get_provider())
render_ai_explanation(ai_explanation)

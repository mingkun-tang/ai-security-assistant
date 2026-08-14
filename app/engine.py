from knowledge import RECOMMENDATIONS, FOLLOW_UP_QUESTIONS

READ_WORDS = ["read", "view", "see", "access", "open", "look", "check"]
MODIFY_WORDS = ["change", "modify", "update", "edit", "mess", "alter"]
DELETE_WORDS = ["delete", "remove", "erase"]
OTHER_USER_WORDS = [
    "another user",
    "other user",
    "someone else",
    "someone else's",
    "another account",
    "other account",
    "their account",
    "their profile"
]
AUTHORIZATION_WORDS = [
    "admin",
    "role change",
    "permission",
    "privilege"
]

DATA_WORDS = [
    "email",
    "profile",
    "account",
    "sensitive data"
]
AUTHENTICATION_WORDS = {
    "login",
    "password",
    "session"
}

USER_DATA_WORDS = ["data", "information", "profile", "account", "stuff", "info", "record", "details"]
EMAIL_WORDS = ["email"]
ROLE_WORDS = ["role", "admin", "boss", "permission", "privilege", "permissions","privileges"]


def normalize_input(user_input):
    data = {
        "action": None,
        "target": None,
        "actor": "user",
        "control_point": None,
        "signals": {
            "ownership":{
                "other_user": False,
                "self_reference": False,
            },
            "authorization": {
                "admin_reference": False,
                "role_change": False,
                "permission_reference": False,
                "privilege_reference": False
            },
            "data":{
                "email_reference": False,
                "profile_reference": False,
                "account_reference": False,
                "sensitive_data_erefence": False
            },
            "authentication": {
                "login_reference": False,
                "password_reference": False,
                "session_reference": False
            }
        }
    }


    #Score with action to determine the linkly hood of something happening
    action_scores = {
        "read": 0,
        "modify": 0,
        "delete": 0
    }

    text = user_input.lower()


    #Day 85 NEED HELP WITH THIS
    #Don't know if I should do this thing for every other authroization, data, authentication.
    data["signals"]["ownership"]["other_user"] = any(
        phrase in text
        for phrase in OTHER_USER_WORDS
    )

    data["signals"]["authorization"]
    ####


    # detect action
    for word in READ_WORDS:
        if word in text:
            action_scores["read"] += 1
    
    # detect modify
    for word in MODIFY_WORDS:
        if word in text:
            action_scores["modify"] += 1
    
    #detect delete action
    for word in DELETE_WORDS:
        if word in text:
            action_scores["delete"] += 1

    # detect target (email)
    if any(word in text for word in EMAIL_WORDS):
        data["target"] = "user email"

    # detect target (user data)
    if any(word in text for word in USER_DATA_WORDS):
        data["target"] = "user data"
    
    # detect target (user role)
    if any(word in text for word in ROLE_WORDS):
        data["target"] = "user role"

    # detection control point
    if "user" in text or "account" in text or "profile" in text:
        data["control_point"] = "user account endpoint"
    
    data["action_scores"] = action_scores

    if max(action_scores.values()) > 0:
        data["action"] = max(action_scores, key=action_scores.get)
    else:
        data["action"] = None

    return data 


    
def analyze(data):
    result= {
        "issue_type": None,
        "missing_control": None, 
        "broken_trust": None,
        "assumption": None, 
        "impact": None
    }


    # modify + email
    if data["action"] == "modify" and data["target"] == "user email":
        result["issue_type"] = "modify_data"
        result["missing_control"] = "authorization check"
        result["broken_trust"] = "user-controlled input is trusted"
        result["assumption"] = "user can only modify their own data"
        result["impact"] = "possible account takeover"
    
    # read + user data
    if data["action"] == "read" and data ["target"] == "user data":
        result["issue_type"] = "idor"
        result["missing_control"] = "authorization check"
        result["broken_trust"] = "user can access data without verification"
        result["assumption"] = "users can only access their own data"
        result["impact"] = "exposure of sensitive user information"

    # modify + user data
    if data["action"] == "modify" and data ["target"] == "user data":
        result["issue_type"] = "modify_data"
        result["missing_control"] = "authorization check"
        result["broken_trust"] = "user-controlled input is trusted"
        result["assumption"] = "users can only modify their own data"
        result["impact"] = "unauthorized modification of sensitive user information"

    # modify + user role 
    if data["action"] == "modify" and data["target"] == "user role":
        result["issue_type"] = "privilege_escalation"
        result["missing_control"] = "role change authorization check"
        result["broken_trust"] = "user is allowed to control their own permissions"
        result["assumption"] = "users cannot assign themselves higher privileges"
        result["impact"] = "privilege escalation and unauthorized access to restricted functionality"

    # delete + user data
    if data["action"] == "delete" and data["target"] == "user data":
        result["issue_type"] = "delete_action"
        result["missing_control"] = "authorization check on destructive action"
        result["broken_trust"] = "user is allowed to perform a dangerous action without proper verification"
        result["assumption"] = "only authorized roles can delete user accounts"
        result["impact"] = "unauthorized account deletion or system disruption"

    if result["issue_type"] is None:
        result ["issue_type"] = "unknown"
        result["missing_control"] = "unknown"
        result["broken_trust"] = "unknown"
        result["assumption"] = "insufficient information to determine"
        result["impact"] = "unable to determine potential impact"

    scores = data.get("action_scores", {})
    values = list(scores.values())

    max_score = max(values) if values else 0
    non_zero = [v for v in values if v > 0]

    if max_score == 0:
        result["confidence"] = "low"
    elif len(non_zero) == 1:
            result["confidence"] = "high"
    else:
        result["confidence"] = "medium"

    return result

def explain_analysis(analysis):
    explanation = {
        "missing_control": "",
        "broken_trust": "",
        "assumption": "",
        "impact": ""
    }

    if analysis["missing_control"] == "authorization check":
        explanation["missing_control"] = (
            "This may indicate a missing authorization check, because the system may not be verifying whether the user is allowed to perform this action."
        )
    elif analysis["missing_control"] == "role change authorization check":
        explanation["missing_control"] = (
            "This may indicate a missing role-change authorization check, because the system may be allowing users to change permissions without verifying if they are allowed to do so."
        )
    elif analysis["missing_control"] == "authorization check on destructive action":
        explanation["missing_control"] = (
            "This may indicate missing protection around a destructive action, because deleting accounts should only be allowed for properly authorized roles."
        )
    elif analysis["missing_control"] == "unknown":
        explanation["missing_control"] =(
            "There is not enough information to confidently identify the missing control yet"
        )
    else:
        explanation["missing_control"] = "No specific missing control was identified."

    if analysis["broken_trust"] == "user-controlled input is trusted":
        explanation["broken_trust"] = (
            "The system appears to trust input controlled by the user. This can be dangerous if that input affects what account, resource, or permission is being changed."
        )
    elif analysis["broken_trust"] == "user can access data without verification":
        explanation["broken_trust"] = (
            "The system appears to allow access to user data without confirming that the requester owns or is allowed to view that data."
        )
    elif analysis["broken_trust"] == "user is allowed to control their own permissions":
        explanation["broken_trust"] = (
            "The system appears to trust the user with permission changes. A normal user should not be able to assign themselves higher privileges."
        )
    elif analysis["broken_trust"] == "user is allowed to perform a dangerous action without proper verification":
        explanation["broken_trust"] = (
            "The system appears to allow a dangerous action without enough verification. Actions like deleting accounts should require strict authorization checks."
        )
    elif analysis["broken_trust"] == "unknown":
        explanation["broken_trust"] = (
            "The broken trust boundary is not clear from the current information."
        )
    else:
        explanation["broken_trust"] = "No specific broken trust boundary was identified."
    
    impact = analysis["impact"]
    explanation['assumption'] = f"The system assumption appears to be: {analysis['assumption']}."
    explanation["impact"] = f"if this continues, the impact could be: {impact}"

    return explanation



def generate_output(user_input, analysis):
    explanation = explain_analysis(analysis)
    confidence = analysis.get("confidence", "low")

    print("\n--- Analysis Result ---\n")

    print("What is happening:")
    print(user_input)

    confidence = analysis.get("confidence", "low")

    if analysis["issue_type"] == "unknown":
        print(f"\n Possible issue ({confidence} confidence):")
    else:
        print(f"\nPossible security issue ({confidence} confidence):")

    print(f"- {explanation['missing_control']}")
    print(f"- {explanation['broken_trust']}")
    print(f"- {explanation['assumption']}")

    print("\nImpact:")
    print(f"- {explanation['impact']}")

    print("\nNext steps:")

    steps = RECOMMENDATIONS.get(analysis["issue_type"], [])

    for step in steps:
        print(f"- {step}")
    
    questions = FOLLOW_UP_QUESTIONS.get(analysis["issue_type"], [])
    if confidence != "high":
        print("\nFollow-up questions:")

        for question in questions:
            print(f"- {question}")
    
    print (normalize_input(user_input))
    
    

    print("\n-----------------------\n")
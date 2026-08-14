
RECOMMENDATIONS = {
    "idor": [
        "Enforce object-level authorization checks",
        "Validate that users can only access their own data",
        "Test by modifying user identifiers in requests"
    ],
    "modify_data":[
        "Verify ownership before allowing modifications",
        "Do not trust user-controlled input for sensitive updates",
        "Add server-side validation for all changes"
    ],
    "privilege_escalation": [
        "Restrict role assignment to authorized roles only",
        "Validate role changes on the server side",
        "Ensure users cannot assign themselves higher privileges"
    ],
    "delete_action": [
        "Restrict destructive actions to authorized roles only",
        "Add confirmation and logging for delete actions",
        "Prevent deletion of critical accounts (ex: last admin)"
    ],
    "unknown":[
    "Review the request and idenify what action is being performed",
    "Check if the action involves another user's data or privileges", 
    "Verify if proper authorization checks exist",
    "try testing with different inputs to observe behavior"
    ]
}

FOLLOW_UP_QUESTIONS = {
    "idor": [
        "Can the action access another user's data?",
        "Does changing the user identifier expose different information?",
        "Is the request properly checking ownership?"
    ],
    "modify_data": [
        "Can another user's information be modified?",
        "Does the server verify ownership before updating data?",
        "Can sensitive fields be changed directly from the request?"
    ],
    "priviledge_escalation": [
        "Can a normal user assign themselves higher privileges?",
        "Does the server validate role changes",
        "Are role changes restricted to administrators?"
    ],
    "delete_action": [
        "Can a normal user delete another account?",
        "Does the system requirement authorization before deletion",
        "Are destructive actions logged or protected?"
    ],
    "unknown": [
        "What action is being performed?",
        "Does the behavior affect another user?",
        "Can the request change or expose sensitive information?"
    ]
}

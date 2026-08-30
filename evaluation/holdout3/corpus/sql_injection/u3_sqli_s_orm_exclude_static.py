class Job:
    objects = None

def active_jobs():
    return Job.objects.exclude(status="archived")

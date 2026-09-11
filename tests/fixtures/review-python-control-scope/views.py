import subprocess

from django.http import JsonResponse
from django.views.generic import View

from .models import Challenge, UserChallenge


class ChallengeRunner(View):
    def post(self, request, challenge):
        chal = Challenge.objects.get(name=challenge)
        user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
        command = f"docker stop {user_chal.container_id}"
        subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)
        return JsonResponse({"status": "stopped"})

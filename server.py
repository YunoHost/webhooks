import os
import hmac
import hashlib
import subprocess

from sanic import Sanic
from sanic.response import text
from sanic.exceptions import abort


app = Sanic()

secret = open("./github_webhook_secret", "r").read().strip()
gitbot_password = open("./gitbot_password", "r").read().strip()

other_chans = {
    "doc": "doc",
}

# TODO
# * choper tous les templates de notification
# * choper tous les evenements à suivre
# * fusionner les 2
# * déployer


def notify(message, chan="dev"):
    print(f"{chan} -> {message}")
    subprocess.check_call(["python", "./to_room.py", gitbot_password, message, chan])


@app.route("/github", methods=['POST'])
async def github(request):
    # Only SHA1 is supported
    header_signature = request.headers.get('X-Hub-Signature')
    if header_signature is None:
        print("no header X-Hub-Signature")
        abort(403)

    sha_name, signature = header_signature.split('=')
    if sha_name != 'sha1':
        print("signing algo isn't sha1, it's '%s'" % sha_name)
        abort(501)

    # HMAC requires the key to be bytes, but data is string
    mac = hmac.new(secret.encode(), msg=request.body, digestmod=hashlib.sha1)

    if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
        abort(403)

    hook_type = request.headers.get("X-Github-Event")

    print(f"Hook type: {hook_type}")

    # https://developer.github.com/v3/activity/events/types/#pushevent
    if hook_type == "push":
        repository = request.json["repository"]["name"]
        commits = request.json["commits"]
        user = request.json["pusher"]["name"]
        branch = request.json["ref"].split("/", 2)[2]

        if len(commits) == 1:
            url = commits[0]["url"]
            notify(f"[{repository}] @{user} pushed {len(commits)} to {branch}: {url}")
        else:
            url = request.json["compare"]
            notify(f"[{repository}] @{user} pushed {len(commits)}s to {branch}: {url}")
            for commit in commits:
                author = commit["author"]["name"]
                commit_message = commit["message"]
                notify(f"[{repository}/{branch}] {commit_message} - {author}")

    # https://developer.github.com/v3/activity/events/types/#commitcommentevent
    elif hook_type == "commit_comment":
        repository = request.json["repository"]["name"]
        user = request.json["comment"]["user"]["login"]
        commit_short_id = request.json["comment"]["commit_id"][:7]
        comment = request.json["comment"]["body"]

        notify(f"[{repository}] @{user} comment on commit {commit_short_id}: {comment} {url}")

    return text("ok")


@app.route("/")
async def index(request):
    return text("Webhooks server.")


if __name__ == '__main__':
    app.run('localhost', port="4567", debug=True)

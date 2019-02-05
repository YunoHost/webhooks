import hmac
import hashlib

from sanic import Sanic
from sanic.response import text
from sanic.exceptions import abort


app = Sanic()

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


@app.route("/github", methods=['POST'])
async def github(request):
    secret = open("./github_webhook_secret", "r").read().strip()

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
                author = commit["author"]
                commit_message = commit["message"]
                notify(f"[{repository}/{branch}] {commit_message} - {author}")

    return text("ok")


@app.route("/")
async def index(request):
    return text("Webhooks server.")


if __name__ == '__main__':
    app.run('localhost', port="4567", debug=True)

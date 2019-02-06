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
            notify(f"[{repository}] @{user} pushed {len(commits)} commit to {branch}: {url}")
        else:
            url = request.json["compare"]
            notify(f"[{repository}] @{user} pushed {len(commits)} commits to {branch}: {url}")
            for commit in commits[-5:]:
                author = commit["author"]["name"]
                commit_message = commit["message"].replace("\r\n", " ")

                if len(commit_message) > 120:
                    commit_message = commit_message[120:] + "..."

                notify(f"[{repository}/{branch}] {commit_message} - {author}")

    # https://developer.github.com/v3/activity/events/types/#commitcommentevent
    elif hook_type == "commit_comment":
        repository = request.json["repository"]["name"]
        user = request.json["comment"]["user"]["login"]
        commit_short_id = request.json["comment"]["commit_id"][:7]
        comment = request.json["comment"]["body"].replace("\r\n", " ")

        notify(f"[{repository}] @{user} comment on commit {commit_short_id}: {comment} {url}")

    # https://developer.github.com/v3/activity/events/types/#createevent
    elif hook_type == "create":
        kind = request.json["ref_type"]
        user = request.json["sender"]["login"]
        repository = request.json["repository"]["name"]

        if kind == "repository":
            notify(f"@{user} created new repository {repository}: {url}")
        elif kind == "branch":
            branch = request.json["ref"]
            notify(f"[{repository}] @{user} created new branch {branch}")
        elif kind == "tag":
            tag = request.json["ref"]
            notify(f"[{repository}] @{user} created new tag {tag}")
        else:
            print(f"WARNING: unknown 'create' event kind: {kind}")

    # https://developer.github.com/v3/activity/events/types/#createevent
    elif hook_type == "delete":
        kind = request.json["ref_type"]
        user = request.json["sender"]["login"]
        repository = request.json["repository"]["name"]

        ref = request.json["ref"]
        notify(f"[{repository}] @{user} deleted {kind} {ref}")

    # https://developer.github.com/v3/activity/events/types/#forkevent
    elif hook_type == "fork":
        repository = request.json["repository"]["name"]
        forked_repository = request.json["forkee"]["full_name"]
        user = request.json["sender"]["login"]
        url = request.json["forkee"]["html_url"]

        notify(f"@{user} forked {repository} to {forked_repository}: {url}")

    # https://developer.github.com/v3/activity/events/types/#issuecommentevent
    elif hook_type == "issue_comment":
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        url = request.json["comment"]["html_url"]
        issue_number = request.json["issue"]["number"]
        issue_title = request.json["issue"]["title"]
        comment = request.json["comment"]["body"].replace("\r\n", " ")

        if len(comment) > 120:
            comment = comment[:120] + "..."

        notify(f"[{repository}] @{user} commented on issue #{issue_number} {issue_title}: {comment} {url}")

    # https://developer.github.com/v3/activity/events/types/#issuesevent
    elif hook_type == "issues":
        action = request.json["action"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        issue_number = request.json["issue"]["number"]
        url = request.json["issue"]["html_url"]
        issue_title = request.json["issue"]["title"]

        if action == "opened":
            notify(f"[{repository}] @{user} {action} issue #{issue_number}: {issue_title} {url}")

        elif action in ("edited", "deleted", "transferred", "pinned",
                        "unpinned", "closed", "reopened"):
            notify(f"[{repository}] @{user} {action} issue #{issue_number}: {issue_title} {url}")

        elif action in ("assigned", "unassigned"):
            assigned_user = request.json["assignee"]
            notify(f"[{repository}] @{user} {action} {assigned_user} on issue #{issue_number}: {issue_title} {url}")

        elif action in ("labeled", "unlabeled"):
            label = request.json["label"]
            notify(f"[{repository}] @{user} {action} {label} on issue #{issue_number}: {issue_title} {url}")

        elif action == "milestoned":
            milestone = request.json["issue"]["milestone"]
            notify(f"[{repository}] @{user} {action} {milestone} issue #{issue_number}: {issue_title} {url}")

        elif action == "demilestoned":
            notify(f"[{repository}] @{user} {action} issue #{issue_number}: {issue_title} {url}")

        else:
            notify(f"WARNING: unknown 'issues' action: {action}")

    # https://developer.github.com/v3/activity/events/types/#labelevent
    elif hook_type == "label":
        action = request.json["action"]
        label = request.json["label"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]

        notify(f"[{repository}] @{user} {action} label {label}")

    # https://developer.github.com/v3/activity/events/types/#milestoneevent
    elif hook_type == "milestone":
        action = request.json["action"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        milestone = request.json["milestone"]["title"]

        notify(f"[{repository}] @{user} {action} milestone {milestone}")

    # https://developer.github.com/v3/activity/events/types/#pullrequestreviewcommentevent
    elif hook_type == "pull_request_review_comment":
        action = request.json["action"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        pull_request_number = request.json["pull_request"]["number"]
        comment = request.json["comment"]["body"].replace("\r\n", " ")
        url = request.json["comment"]["html_url"]

        if len(comment) > 120:
            comment = comment[:120] + "..."

        notify(f"[{repository}] @{user} {action} a comment on pull request #{pull_request_number}: {comment} {url}")

    # https://developer.github.com/v3/activity/events/types/#pullrequestreviewevent
    elif hook_type == "pull_request_review":
        action = request.json["action"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        pull_request_number = request.json["pull_request"]["number"]
        pull_request_title = request.json["pull_request"]["title"]

        if action == "submitted":
            state = request.json["review"]["state"]
            comment = request.json["review"]["body"].replace("\r\n", " ")
            if comment and len(comment) > 120:
                comment = ": " + comment[:120] + "..."
            elif not comment:
                comment = ""
            else:
                comment = ": " + comment

            notify(f"[{repository}] @{user} {state} pull request #{pull_request_number} {pull_request_title}{comment} {url}")

        else:
            notify(f"[{repository}] @{user} {action} review pull request #{pull_request_number}: {pull_request_title} {url}")

    # https://developer.github.com/v3/activity/events/types/#pullrequestevent
    elif hook_type == "pull_request":
        action = request.json["action"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        pull_request_number = request.json["pull_request"]["number"]
        pull_request_title = request.json["pull_request"]["title"]
        url = request.json["pull_request"]["html_url"]
        comment = request.json["pull_request"]["body"].replace("\r\n", " ")

        if action in ("opened", "edited", "deleted", "transferred", "pinned",
                      "unpinned", "reopened"):
            notify(f"[{repository}] @{user} {action} pull_request #{pull_request_number}: {pull_request_title} {url}")

        elif action in ("labeled", "unlabeled"):
            label = request.json["label"]
            notify(f"[{repository}] @{user} {action} {label} on issue #{issue_number}: {issue_title} {url}")

        elif action == "closed":
            if request.json["pull_request"]["merged"]:
                action = "merged"
            notify(f"[{repository}] @{user} {action} {milestone} pull_request #{pull_request_number}: {pull_request_title} {url}")

        # super weird, this action is not supposed to be possible for pull_request :|
        elif action == "milestoned":
            milestone = request.json["pull_request"]["milestone"]
            notify(f"[{repository}] @{user} {action} {milestone} pull_request #{pull_request_number}: {pull_request_title} {url}")

        # super weird, this action is not supposed to be possible for pull_request :|
        elif action == "demilestoned":
            notify(f"[{repository}] @{user} {action} pull_request #{pull_request_number}: {pull_request_title} {url}")

        elif action in ("review_requested", "review_request_removed", "synchronize"):
            pass  # we don't care about those...

        else:
            notify(f"WARNING: unknown 'pull_requests' action: {action}")

    # https://developer.github.com/v3/activity/events/types/#repositoryevent
    elif hook_type == "repository":
        action = request.json["action"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        url = request.json["repository"]["html_url"]
        description = request.json["repository"]["description"]

        if not description:
            description = ""
        else:
            description = ": " + description

        notify(f"@{user} {action} repository {repository}{description} {url}")

    # https://developer.github.com/v3/activity/events/types/#releaseevent
    elif hook_type == "release":
        action = request.json["action"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        url = request.json["release"]["html_url"]
        release_tag = request.json["release"]["tag_name"]
        release_title = request.json["release"]["name"]

        notify(f"[repository] @{user} {action} new release #{release_tag} {release_title} {url}")

    # https://developer.github.com/v3/activity/events/types/#statusevent
    elif hook_type == "status":
        state = request.json["state"]
        description = request.json["description"]
        target_url = request.json["target_url"]
        repository = request.json["repository"]["name"]
        user = request.json["sender"]["login"]
        url = request.json["commit"]["html_url"]

        print(f"Status weird stuff: [{repository}] @{user} state: {state}, description: {description}, target_url: {target_url} - {url}")

    return text("ok")


@app.route("/")
async def index(request):
    return text("Webhooks server.")


if __name__ == '__main__':
    app.run('localhost', port="4567", debug=True)

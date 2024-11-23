import hmac
import hashlib
import asyncio

from sanic import Sanic
from sanic.response import text
from sanic.exceptions import abort


app = Sanic(name="Webhooks")

secret = open("./github_webhook_secret", "r").read().strip()
gitbot_password = open("./gitbot_password", "r").read().strip()


CHANNELS = {
    "dev": "!oUChrIGPjhUkpgjYCW:matrix.org",
    "apps": "!PauySEslPVuJCJCwlZ:matrix.org",
    "doc": "!OysWrSrQatFMrZROPJ:aria-net.org",
}

SPECIFIC_REPO_TO_CHANNEL_MAPPING = {
    "doc": "doc",
    "apps": "apps",
    "appstore": "apps",
    "apps_tools": "apps",
    "apps_tools": "apps",
    "appgenerator": "apps",
    "example_ynh": "apps",
    "package_linter": "apps",
    "package_check": "apps",
}

# TODO
# * choper tous les templates de notification
# * choper tous les evenements à suivre
# * fusionner les 2
# * déployer

APP_DIR = "/var/www/my_webapp"


async def notify(message, repository="dev"):
    if repository.endswith("_ynh"):
        chan = CHANNELS["apps"]
    else:
        chan = CHANNELS[SPECIFIC_REPO_TO_CHANNEL_MAPPING.get(repository, "dev")]

    print(f"{chan} -> {message}")

    for char in ["'", "`", "!", ";", "$"]:
        message = message.replace(char, "")

    command = f"{APP_DIR}/matrix-commander --markdown -m '{message}' -c {APP_DIR}/credentials.json --store {APP_DIR}/store --sync off --room '{chan}'"
    proc = await asyncio.create_subprocess_shell(command)
    try:
        await proc.communicate()
        await proc.wait()
    except Exception as e:
        print(f"Found exception {e}")
        if type(e).__name__ == "CancelledError":
            pass
        else:
            raise Exception(
                f" {type(e).__name__} while trying to notify about commit '{commit_message}' on {repository}/{branch}: {e}"
            )


@app.route("/github", methods=["GET"])
async def github_get(request):
    return text(
        "You aren't supposed to go on this page using a browser, it's for webhooks push instead."
    )


@app.route("/github", methods=["POST"])
async def github(request):
    # Only SHA1 is supported
    header_signature = request.headers.get("X-Hub-Signature")
    if header_signature is None:
        print("no header X-Hub-Signature")
        abort(403)

    sha_name, signature = header_signature.split("=")
    if sha_name != "sha1":
        print("signing algo isn't sha1, it's '%s'" % sha_name)
        abort(501)

    # HMAC requires the key to be bytes, but data is string
    mac = hmac.new(secret.encode(), msg=request.body, digestmod=hashlib.sha1)

    if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
        abort(403)

    hook_type = request.headers.get("X-Github-Event")

    print()
    print(f"Hook type: {hook_type}")

    def user_noping(user: str) -> str:
        # Add an invisible character to prevent pinging the user
        # if their Matrix and github nickname are the same
        return user[0] + "​" + user[1:]

    try:
        repository = request.json.get("repository", {}).get("name")

        # do not notify if the repo is 'apps_translations'
        if repository == "apps_translations":
            return

        # https://developer.github.com/v3/activity/events/types/#pushevent
        if hook_type == "push":
            commits = request.json["commits"]
            user = user_noping(request.json["pusher"]["name"])

            branch = request.json["ref"].split("/", 2)[2]

            if len(commits) == 1:
                url = commits[0]["url"]
                commit_message = (
                    commits[0]["message"].replace("\r\n", " ").replace("\n", " ")
                )

                if len(commit_message) > 120:
                    commit_message = commit_message[:120] + "..."

                commit_id = url.split("/")[-1][:8]
                await notify(
                    f"[{repository}] {user} pushed {len(commits)} commit to {branch}: {commit_message} ([{commit_id}]({url}))",
                    repository=repository,
                )
            elif len(commits) > 1:
                url = request.json["compare"]
                commit_ids = url.split("/")[-1]
                await notify(
                    f"[{repository}] {user} pushed {len(commits)} commits to {branch} ([{commit_ids}]({url}))",
                    repository=repository,
                )
                for commit in commits[-3:]:
                    author = commit["author"]["name"]
                    commit_message = (
                        commit["message"].replace("\r\n", " ").replace("\n", " ")
                    )

                    if len(commit_message) > 120:
                        commit_message = commit_message[:120] + "..."

                    await notify(
                        f"[{repository}/{branch}] {commit_message} - {author}",
                        repository=repository,
                    )
            else:
                ...  # case of 0 which means branch deletion

        # https://developer.github.com/v3/activity/events/types/#commitcommentevent
        elif hook_type == "commit_comment":
            user = user_noping(request.json["comment"]["user"]["login"])
            commit_short_id = request.json["comment"]["commit_id"][:7]
            comment = request.json["comment"]["body"].replace("\r\n", " ")
            url = request.json["comment"]["html_url"]

            await notify(
                f"[{repository}] {user} [comment]({url}) on commit {commit_short_id}: {comment}",
                repository=repository,
            )

        # https://developer.github.com/v3/activity/events/types/#createevent
        elif hook_type == "create":
            kind = request.json["ref_type"]
            user = user_noping(request.json["sender"]["login"])

            if kind == "repository":
                await notify(
                    f"{user} created new repository {repository}",
                    repository=repository,
                )
            elif kind == "branch":
                branch = request.json["ref"]
                await notify(
                    f"[{repository}] {user} created new branch {branch}",
                    repository=repository,
                )
            elif kind == "tag":
                tag = request.json["ref"]
                await notify(
                    f"[{repository}] {user} created new tag {tag}",
                    repository=repository,
                )
            else:
                print(f"WARNING: unknown 'create' event kind: {kind}")

        # https://developer.github.com/v3/activity/events/types/#createevent
        elif hook_type == "delete":
            kind = request.json["ref_type"]
            user = user_noping(request.json["sender"]["login"])

            ref = request.json["ref"]
            await notify(
                f"[{repository}] {user} deleted {kind} {ref}", repository=repository
            )

        # https://developer.github.com/v3/activity/events/types/#forkevent
        elif hook_type == "fork":
            forked_repository = request.json["forkee"]["full_name"]
            user = user_noping(request.json["sender"]["login"])
            url = request.json["forkee"]["html_url"]

            await notify(
                f"{user} forked {repository} to [{forked_repository}]({url})",
                repository=repository,
            )

        # https://developer.github.com/v3/activity/events/types/#issuecommentevent
        elif hook_type == "issue_comment":
            user = user_noping(request.json["sender"]["login"])
            url = request.json["comment"]["html_url"]
            issue_url = request.json["issue"]["html_url"]
            issue_number = request.json["issue"]["number"]
            issue_title = request.json["issue"]["title"]
            comment = request.json["comment"]["body"].replace("\r\n", " ")

            if len(comment) > 120:
                comment = comment[:120] + "..."

            await notify(
                f"[{repository}] {user} [commented]({url}) on [issue #{issue_number}]({issue_url}) {issue_title}: {comment}",
                repository=repository,
            )

        # https://developer.github.com/v3/activity/events/types/#issuesevent
        elif hook_type == "issues":
            action = request.json["action"]
            user = user_noping(request.json["sender"]["login"])
            issue_number = request.json["issue"]["number"]
            url = request.json["issue"]["html_url"]
            issue_title = request.json["issue"]["title"]

            if action == "opened":
                await notify(
                    f"[{repository}] {user} {action} [issue #{issue_number}]({url}): {issue_title}",
                    repository=repository,
                )

            elif action in (
                "edited",
                "deleted",
                "transferred",
                "pinned",
                "unpinned",
                "closed",
                "reopened",
            ):
                await notify(
                    f"[{repository}] {user} {action} [issue #{issue_number}]({url}): {issue_title}",
                    repository=repository,
                )

            elif action in ("assigned", "unassigned"):
                assigned_user = request.json["assignee"]["login"]
                await notify(
                    f"[{repository}] {user} {action} {assigned_user} on [issue #{issue_number}]({url}): {issue_title}",
                    repository=repository,
                )

            elif action in ("labeled", "unlabeled"):
                label = request.json["label"]["name"]
                await notify(
                    f"[{repository}] {user} {action} {label} on [issue #{issue_number}]({url}): {issue_title}",
                    repository=repository,
                )

            elif action == "milestoned":
                milestone = request.json["issue"]["milestone"]["title"]
                await notify(
                    f"[{repository}] {user} set {milestone} on [issue #{issue_number}]({url}): {issue_title}",
                    repository=repository,
                )

            elif action == "demilestoned":
                await notify(
                    f"[{repository}] {user} {action} [issue #{issue_number}]({url}): {issue_title}",
                    repository=repository,
                )

            else:
                await notify(
                    f"[{repository}] WARNING: unknown 'issues' action: {action}",
                    repository=repository,
                )

        # https://developer.github.com/v3/activity/events/types/#labelevent
        elif hook_type == "label":
            action = request.json["action"]
            label = request.json["label"]["name"]
            user = user_noping(request.json["sender"]["login"])

            await notify(
                f"[{repository}] {user} {action} label {label}", repository=repository
            )

        # https://developer.github.com/v3/activity/events/types/#milestoneevent
        elif hook_type == "milestone":
            action = request.json["action"]
            user = user_noping(request.json["sender"]["login"])
            milestone = request.json["milestone"]["title"]

            await notify(
                f"[{repository}] {user} {action} milestone {milestone}",
                repository=repository,
            )

        # https://developer.github.com/v3/activity/events/types/#pullrequestreviewcommentevent
        elif hook_type == "pull_request_review_comment":
            action = request.json["action"]
            user = user_noping(request.json["sender"]["login"])
            pull_request_number = request.json["pull_request"]["number"]
            pull_request_title = request.json["pull_request"]["title"]
            comment = request.json["comment"]["body"].replace("\r\n", " ")
            url = request.json["comment"]["html_url"]

            if len(comment) > 120:
                comment = comment[:120] + "..."

            if action == "created":
                await notify(
                    f"[{repository}] {user} [commented]({url}) on pull request #{pull_request_number} {pull_request_title}: {comment}",
                    repository=repository,
                )
            else:
                await notify(
                    f"[{repository}] {user} {action} a [comment]({url}) on pull request #{pull_request_number} {pull_request_title}: {comment}",
                    repository=repository,
                )

        # https://developer.github.com/v3/activity/events/types/#pullrequestreviewevent
        elif hook_type == "pull_request_review":
            action = request.json["action"]
            user = user_noping(request.json["sender"]["login"])
            pull_request_number = request.json["pull_request"]["number"]
            pull_request_title = request.json["pull_request"]["title"]
            url = request.json["review"]["html_url"]

            if action == "submitted":
                state = request.json["review"]["state"]
                comment = request.json["review"]["body"]
                if comment and len(comment) > 120:
                    comment = ": " + comment[:120].replace("\r\n", " ") + "..."
                elif not comment:
                    comment = ""
                else:
                    comment = ": " + comment.replace("\r\n", " ")

                # to avoid duplicated with pull_request_review_comment event
                if state == "commented" and not comment:
                    pass
                else:
                    await notify(
                        f"[{repository}] {user} {state} [pull request #{pull_request_number}]({url}) {pull_request_title}{comment}",
                        repository=repository,
                    )

            else:
                await notify(
                    f"[{repository}] {user} {action} review [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

        # https://developer.github.com/v3/activity/events/types/#pullrequestevent
        elif hook_type == "pull_request":
            action = request.json["action"]
            user = user_noping(request.json["sender"]["login"])
            pull_request_number = request.json["pull_request"]["number"]
            pull_request_title = request.json["pull_request"]["title"]
            url = request.json["pull_request"]["html_url"]
            comment = request.json["pull_request"]["body"]

            if comment and len(comment) > 120:
                comment = ": " + comment[:120].replace("\r\n", " ") + "..."
            elif not comment:
                comment = ""
            else:
                comment = ": " + comment.replace("\r\n", " ")

            if action in (
                "opened",
                "edited",
                "deleted",
                "transferred",
                "pinned",
                "unpinned",
                "reopened",
            ):
                await notify(
                    f"[{repository}] {user} {action} [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            elif action in ("labeled", "unlabeled"):
                label = request.json["label"]["name"]
                await notify(
                    f"[{repository}] {user} {action} {label} on [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            elif action == "closed":
                if request.json["pull_request"]["merged"]:
                    action = "merged"
                await notify(
                    f"[{repository}] {user} {action} [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            elif action == "ready_for_review":
                await notify(
                    f"[{repository}] {user} just made [pull request #{pull_request_number}]({url}) ready for review: {pull_request_title}",
                    repository=repository,
                )

            # super weird, this action is not supposed to be possible for pull_request :|
            elif action == "milestoned":
                milestone = request.json["pull_request"]["milestone"]
                await notify(
                    f"[{repository}] {user} set {milestone} [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            # super weird, this action is not supposed to be possible for pull_request :|
            elif action == "demilestoned":
                await notify(
                    f"[{repository}] {user} {action} [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            elif action == "converted_to_draft":
                await notify(
                    f"[{repository}] {user} converted to draft the [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            elif action == "assigned":
                assigned_user = request.json["assignee"]["login"]
                await notify(
                    f"[{repository}] {user} {action} {assigned_user} on [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            elif action == "auto_merge_enabled":
                await notify(
                    f"[{repository}] Auto-merge has been enabled by {user} on [pull request #{pull_request_number}]({url}): {pull_request_title}",
                    repository=repository,
                )

            elif action in (
                "review_requested",
                "review_request_removed",
                "synchronize",
            ):
                pass  # we don't care about those...

            else:
                await notify(
                    f"WARNING: unknown 'pull_request' action: {action}",
                    repository=repository,
                )

        # https://developer.github.com/v3/activity/events/types/#repositoryevent
        elif hook_type == "repository":
            action = request.json["action"]
            user = user_noping(request.json["sender"]["login"])
            url = request.json["repository"]["html_url"]
            description = request.json["repository"]["description"]

            if not description:
                description = ""
            else:
                description = ": " + description

            await notify(
                f"{user} {action} repository {repository}{description} {url}",
                repository=repository,
            )

        # https://developer.github.com/v3/activity/events/types/#releaseevent
        elif hook_type == "release":
            action = request.json["action"]
            user = user_noping(request.json["sender"]["login"])
            url = request.json["release"]["html_url"]
            release_tag = request.json["release"]["tag_name"]
            release_title = request.json["release"]["name"]

            await notify(
                f"[repository] {user} {action} [new release #{release_tag}]({url}) {release_title}",
                repository=repository,
            )

        # https://developer.github.com/v3/activity/events/types/#statusevent
        elif hook_type == "status":
            state = request.json["state"]
            description = request.json["description"]
            target_url = request.json["target_url"]
            user = user_noping(request.json["sender"]["login"])
            url = request.json["commit"]["html_url"]
            commit_message = request.json["commit"]["commit"]["message"].replace(
                "\n", " "
            )
            if request.json["commit"]["commit"]["committer"]:
                commit_author = request.json["commit"]["commit"]["committer"]["name"]
            else:
                commit_author = request.json["commit"]["commit"]["author"]["name"]
            branches = ", ".join((x["name"] for x in request.json["branches"]))

            if state not in ("success", "pending"):
                if description == "Pipeline failed on GitLab":
                    pipeline_id = target_url.split("/")[-1]
                    await notify(
                        f"[{repository}] 🔴 Pipeline [#{pipeline_id}]({target_url}) failed on branch {branches}"
                    )
                elif description == "Pipeline canceled on GitLab":
                    pipeline_id = target_url.split("/")[-1]
                    await notify(
                        f"[{repository}] ✖️ Pipeline [#{pipeline_id}]({target_url}) canceled on branch {branches}"
                    )
                else:
                    await notify(
                        f'[{repository}] {description} {target_url} on commit {url} "{commit_message}" by @{commit_author} on branch{"es" if len(branches) > 1 else ""} {branches}'
                    )
            else:
                print(
                    f"Status weird stuff: [{repository}] {user} state: {state}, description: {description}, target_url: {target_url} - {url}"
                )

        return text("ok")

    except Exception as e:
        import traceback

        traceback.print_exc()

        try:
            print(request.json)
        except Exception():
            pass

        await notify(
            f"Error in Webhooks: exception {e} on {hook_type} webhooks, please see logs"
        )
        abort(500)


@app.route("/")
async def index(request):
    return text("Webhooks server.")


if __name__ == "__main__":
    app.run("127.0.0.1", port="4567")

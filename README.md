# datatrails-shell

Repository for convenience scripts for the DataTrails system.

# Development

## Pre-requisites

Required tools for this repo are task-runner and shellcheck.

   - Install task runner: https://github.com/go-task/task
   - Install shellcheck: https://github.com/koalaman/shellcheck#user-content-installing

## Workflow

### Preparation

Reference: https://gist.github.com/Chaser324/ce0505fbed06b947d962

Fork the repo using the 'Fork' dialog at the top right corner of the github UI.

Clone the new fork into your local development environment (assuming your github
login is 'githubUserHandle'):

> Note: all references to 'git@github.com' assume that your local github user has adequate
> rights. If using ~/.ssh/config to manage ssh identities then replace all mentions of
> 'git@github.com' with the clause name in ~/.ssh/config which references the appropriate
> ssh key::
> 
> For example:
```
Host ssh-githubUserHandle
    User git
    Hostname github.com
    PreferredAuthentications publickey
    IdentityFile ~/.ssh/id_rsa_githubUserHandle

Host ssh-otherUserHandle
    User git
    Hostname github.com
    PreferredAuthentications publickey
    IdentityFile ~/.ssh/id_rsa_otherUserHandle

Host *
    IdentitiesOnly yes

```
> i.e. 'githubUserHandle' viz:
>
>    git clone ssh-githubUserHandle:githubUserHandle/datatrails-shell.git
>


```bash
mkdir githubUserHandle
cd githubUserHandle
git clone ssh-githubUserHandle:githubUserHandle/datatrails-shell.git
```

Enter the new cloned fork and add the original upstream repo as a remote:

```bash
cd datatrails-shell
git remote add upstream ssh-githubUserHandle:datatrails/datatrails-shell.git
git remote -v
```

Now add a branch for your proposed changes:

```bash
git status
git checkout -b dev/githubUserHandle/some-proposed-fix
git status
```

### Making changes

To see what options are available simply execute:

```bash
task
```

Make a change to the code and validate the changes:

```bash
task check
```

And then test changes with a working set of options:

```bash
task build-scraper
task scrape -- -h
task scrape -- -a "DataTrails, Inc" \
               -e support@datatrails.ai \
               -A Docker \
               -c credentials/client_secret \
               -u https://app.datatrails.ai \
               8f8f2467-01fe-48fb-891a-5c0be643cec1 \
               aerospike:ce-6.0.0.5
```

### Seeking a review

#### Synchronizing the upstream

Bring in latest changes from upstream:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git checkout dev/githubUserHandle/some-proposed-fix
git rebase -i --autosquash main
```

Ensure that your email and name are correct:

```bash
git config user.name
git config user.email
```

#### Pushing changes upstream

Add all changes to a commit using the **example-commit** file as a template
for the commit message.

```bash
git add .
git commit
```

Push the changes upstream(the set-upstream option is only required the first time this is executed):

```bash
git push --set-upstream origin dev/githubUserHandle/some-proposed-fix
```

Enter the github ui at https://github.com/datatrails/datatrails-shell and 
generate a pull request.

Reviewers will be notified when a PR is generated and you will receive feedback.
Reviewers will trigger QC checks on your code. Failure will result in
automatic rejection.

#### Making further changes

If changes are requested push the changes as a fixup:

```bash
git add .
git commit --fixup HEAD
git push
```

#### Removing Fixups After Reviewer Approval

Eventually the reviewer(s) will approve your changes. At this point you must
squash all your fixups after syncing upstream:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git checkout dev/githubUserHandle/some-proposed-fix
git rebase -i --autosquash main
git push -f
```

#### PR is merged.

The reviewer will then merge your PR into main.

At this point one must tidy up the local fork:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git log
git branch -d dev/githubUserHandle/some-proposed-fix
```


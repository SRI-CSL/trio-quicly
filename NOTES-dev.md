# NOTES on setting up developer environment

## Dependency Management with Poetry

If you need to install `poetry` do so *outside* of this project per https://python-poetry.org/docs/#installing-with-pipx
```
$ brew install pipx
$ cd ~
$ python3 -m venv venv  # assuming you have a recent Python 3
$ source venv/bin/activate
(venv)$ pipx install poetry

# maybe do the following (if advised):
$ pipx ensurepath
$ source ~/.bashrc
```
or using this script:
```
$ curl -sSL https://install.python-poetry.org | python3 -
```

Once you have `poetry` do:
```
$ poetry install
```

Investigating dependencies:
```
$ poetry show
$ poetry show --tree
$ poetry show --tree --why cffi  # to see which dependencies require `cffi`
```

## Developing and Testing in Poetry

To run your script simply use `poetry run python your_script.py`. 

Develop in Python 3.10: `$ poetry env use python3.10`

To run tests in development Python: `$ poetry run pytest`

To run all tests in all supported Python versions, use `$ poetry run tox`
See also: https://pytest-with-eric.com/automation/pytest-tox-poetry/#Step-by-step-guide-on-setting-up-a-project-with-these-tools

TODO: add other test env's like "coverage"

## Building and Publishing

```
$ poetry build
$ poetry publish  # need credentials!
```
See also for GitHub Actions integration: https://github.com/ethho/poetry-demo

## Generating Documentation

To generate the TXT and HTML versions of the specification (in Markdown) locally, use `make` after installing 
required tooling .  Our GitHub automation also creates this online upon merges on `main`.


## Troubleshooting

Currently, updating minor versions of Python 3.x via Homebrew breaks `poetry` so we can reinstall using:
(see also https://github.com/python-poetry/install.python-poetry.org/issues/71)

```bash
curl -sSL https://install.python-poetry.org | python3 - --uninstall
curl -sSL https://install.python-poetry.org | python3
```
To recreate `poetry` environment and reinstall the packages for the Poetry environment in the current working directory:
(see also for more Poetry fixes: https://stackoverflow.com/a/70064450/3816489)

```bash
# Enter the current Poetry environment
poetry shell

# Remove the current environment as referred by path to Python interpreter 
poetry env remove $(which python)

# Reinstall from Poetry's cache
poetry install
```

Note, since Poetry v2.0.0, the `shell` command changed:
```
Since Poetry (2.0.0), the shell command is not installed by default. You can use,

  - the new env activate command (recommended); or
  - the shell plugin to install the shell command

Documentation: https://python-poetry.org/docs/managing-environments/#activating-the-environment

Note that the env activate command is not a direct replacement for shell command.
```
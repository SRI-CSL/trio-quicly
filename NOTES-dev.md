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

TODO...
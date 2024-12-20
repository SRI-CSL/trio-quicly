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

## Developing and Testing in Poetry Virtual Env

To run your script simply use `poetry run python your_script.py`. Likewise if you have command line tools such as 
`pytest` or `black` you can run them using `poetry run pytest`.

TODO...

## Building

```
$ poetry build
```

## Generating Documentation

and uploading, too?...

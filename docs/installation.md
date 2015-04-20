# Installation

# Using uv

[pip] is an extremely fast Python package installer.
You can use it to install `joselib` and try it out:

```console
$ uv pip install pathurl
```

# Using a PEP 621 compliant build backend

[PEP 621] is the standard way to store your dependencies in a `pyproject.toml` file.
You can add `joselib` to your `pyproject.toml` file:

```toml
[project]
dependencies = [
    "joselib~=0.1",
    ....
]
```

## Python Version Requirement

Please note that `joselib` requires Python 3.9 or higher. Please ensure
that you have such a version installed in your system. If not,
consider using a tool like [pyenv] to create a shell with the required Python version.

[uv]: https://github.com/astral-sh/uv
[PEP 621]: https://peps.python.org/pep-0621/
[pyenv]: https://github.com/pyenv/pyenv

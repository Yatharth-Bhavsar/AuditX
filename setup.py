from setuptools import setup, find_packages

setup(
    name="auditx",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.1.0",
        "google-generativeai>=0.8.0",
        "tree-sitter>=0.21.0",
        "tree-sitter-python>=0.21.0",
        "tree-sitter-javascript>=0.21.0",
        "jinja2>=3.1.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.0.0",
        "flask>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "auditx=auditx.cli:cli",
        ],
    },
)

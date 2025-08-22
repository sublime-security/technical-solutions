from setuptools import setup, find_namespace_packages

setup(
    name="stats-report",
    version="0.1.0",
    packages=find_namespace_packages(include=["*"]),
    install_requires=[
        "aiofiles>=23.2.1",
        "aiohttp>=3.9.1",
        "aiosqlite>=0.19.0",
        "urllib3>=2.1.0",
    ],
    python_requires=">=3.8",
)
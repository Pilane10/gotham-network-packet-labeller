from setuptools import setup, find_packages


setup(
    name="my_pipeline",
    version="0.1.0",
    author="Othmane Belarbi",
    author_email="BelarbiO@cardiff.ac.uk",
    keywords=[
        "network intrusion detection",
        "dataset",
        "internet of things",
        "federated learning",
    ],
    packages=find_packages(where="."),
    description="A pipeline for labeling network traffic data in IoT systems",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.11.2",
    install_requires=[
        line.rstrip("") for line in open("./requirements.txt", "r").readlines()
    ],
    dependency_links=[],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Operating System :: OS Independent",
    ],
)

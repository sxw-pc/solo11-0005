"""固漏巡检仪安装配置。"""

from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).parent
readme = ROOT / "docs" / "README.md"
setup(
    name="firm-audit",
    version="1.0.0",
    description="纯离线 IoT 固件文件系统静态安全巡检工具",
    long_description=readme.read_text(encoding="utf-8") if readme.exists() else "",
    long_description_content_type="text/markdown",
    author="Firm Audit Contributors",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=("tests", "tests.*")),
    include_package_data=True,
    package_data={
        "firm_audit": ["rules/*.yaml"],
        "firm_audit.web": ["templates/*.html", "static/css/*.css", "static/js/*.js"],
        "firm_audit.report": ["*.html"],
    },
    install_requires=["Flask>=2.3", "PyYAML>=6.0", "Jinja2>=3.1"],
    entry_points={"console_scripts": ["firm_audit=firm_audit.cli:main"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)

# Hermetic tests: never load a developer's real .env (it may hold provider /
# AI API keys and let tests reach paid services). Package init runs before any
# test module here imports ioc_enricher.utils.config. (A conftest.py is not
# used because tests/ and ioc_enricher/tests/ share the package name "tests".)
# The app log stays on the console (captured by pytest): the default LOG_FILE
# is logs/ioc_enricher.log under the working directory — the real runtime log.
import os as _os

_os.environ["IOC_ENRICHER_DOTENV"] = "0"
_os.environ["LOG_FILE"] = ""

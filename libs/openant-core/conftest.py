# The parsers/<lang>/test_pipeline.py files are CLI pipeline orchestrators (run as scripts), not
# pytest tests. Their shared basename + script-only bare imports make pytest mis-collection fail
# with import-file-mismatch under `pytest parsers/`. Exclude them from collection.
collect_ignore_glob = ["parsers/*/test_pipeline.py"]

# Submission samples

Synthetic [SC-Submission v1](../../docs/specs/submission-v1.md) documents, for implementers and the tests. Every host is reserved (`.example`), every network a documentation range, and every id made up: none of it was collected or reported.

| File | Shows |
|---|---|
| [`sc-submission-v1-example.json`](sc-submission-v1-example.json) | One of each evidence type: archive, scan-service and GH Archive references, log lines, a signed request, an indicator. |

Validate a document against the [schema](../../schemas/sc-submission-v1.json):

```sh
python -c "import json, jsonschema; jsonschema.Draft202012Validator(json.load(open('schemas/sc-submission-v1.json'))).validate(json.load(open('samples/submissions/sc-submission-v1-example.json')))"
```

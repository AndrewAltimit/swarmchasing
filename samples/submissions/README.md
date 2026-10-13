# Submission samples

Synthetic [SC-Submission v1](../../docs/specs/submission-v1.md) documents, and reports in the [other formats the inbox takes](../../docs/specs/submission-v1.md#accepted-formats), for implementers and the tests. Every host is reserved (`.example`), every network a documentation range, and every id made up: none of it was collected or reported.

| File | Shows |
|---|---|
| [`sc-submission-v1-example.json`](sc-submission-v1-example.json) | One of each evidence type: archive, scan-service and GH Archive references, log lines, a signed request, an indicator. |
| [`stix-2.1-bundle-example.json`](stix-2.1-bundle-example.json) | A STIX bundle: report, indicator, observed data with HTTP traffic, sighting, references by id, and an unmapped attack pattern. |
| [`xarf-v4-example.json`](xarf-v4-example.json) | An X-ARF v4 report with a log excerpt and a signed request as evidence. |
| [`iodef-v2-example.xml`](iodef-v2-example.xml) | An IODEF v2 incident with source and target systems, a log record and references by URL. |

Validate a document against the [schema](../../schemas/sc-submission-v1.json):

```sh
python -c "import json, jsonschema; jsonschema.Draft202012Validator(json.load(open('schemas/sc-submission-v1.json'))).validate(json.load(open('samples/submissions/sc-submission-v1-example.json')))"
```

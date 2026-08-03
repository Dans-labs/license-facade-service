# Quick Reference: Complete License JSON Response

## Endpoints Return Complete Data

Both endpoints now return **identical complete JSON** with all fields:

```bash
GET /licenses/{id}
GET /licenses/{id}/json
```

## All Fields Included

✅ uri  
✅ isDeprecatedLicenseId  
✅ **licenseText** (full text)  
✅ **standardLicenseTemplate** (template)  
✅ name  
✅ licenseId  
✅ **crossRef** (cross-references array)  
✅ seeAlso  
✅ isOsiApproved  
✅ **licenseTextHtml** (HTML version)  
✅ isFsfLibre (if available)  

## Examples

### Get Complete xzoom License
```bash
curl http://localhost:12104/licenses/xzoom | jq '.'
```

### Get License Text
```bash
curl http://localhost:12104/licenses/MIT | jq '.licenseText'
```

### Get HTML Version
```bash
curl http://localhost:12104/licenses/MIT | jq '.licenseTextHtml'
```

### Get Template
```bash
curl http://localhost:12104/licenses/MIT | jq '.standardLicenseTemplate'
```

### Get Cross References
```bash
curl http://localhost:12104/licenses/MIT | jq '.crossRef'
```

### Search by UUID
```bash
UUID=$(curl -s http://localhost:12104/licenses/MIT | jq -r '.uri' | rev | cut -d'/' -f1 | rev)
curl http://localhost:12104/licenses/$UUID | jq '.'
```

### Both Endpoints Identical
```bash
# These return the same data:
curl http://localhost:12104/licenses/MIT | jq '.' > /tmp/id.json
curl http://localhost:12104/licenses/MIT/json | jq '.' > /tmp/json.json
diff /tmp/id.json /tmp/json.json  # No output = identical
```

## Response Example (xzoom)

```json
{
  "uri": "https://lfs.labs.dansdemo.nl/api/v1/licenses/060c9113-340d-587f-94bd-fccbf86c04d8",
  "isDeprecatedLicenseId": false,
  "licenseText": "Copyright Itai Nahshon 1995, 1996...",
  "standardLicenseTemplate": "<<var;name=\"copyright\"...>>",
  "name": "xzoom License",
  "licenseId": "xzoom",
  "crossRef": [...],
  "seeAlso": [...],
  "isOsiApproved": false,
  "licenseTextHtml": "<div class=\"replaceable-license-text\">..."
}
```

## Search Methods

All work identically:
- By ID: `GET /licenses/MIT`
- By UUID: `GET /licenses/060c9113-340d-587f-94bd-fccbf86c04d8`
- By JSON: `GET /licenses/MIT/json`
- By UUID+JSON: `GET /licenses/060c9113-340d-587f-94bd-fccbf86c04d8/json`

## Deployment

```bash
docker compose build
docker compose down
docker compose up -d
curl http://localhost:12104/licenses/xzoom | jq '.licenseId'  # Should return: "xzoom"
```

---

**Both endpoints now return complete license data from cached files!** ✅


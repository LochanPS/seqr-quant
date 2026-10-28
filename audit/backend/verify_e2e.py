import asyncio
import httpx

BASE = "http://localhost:8000"


async def main():
    async with httpx.AsyncClient(base_url=BASE) as client:

        print("1. Health check...")
        r = await client.get("/api/v1/health")
        assert r.status_code == 200
        print(f"   {r.json()}")

        print("2. Register...")
        r = await client.post("/api/v1/auth/register", json={
            "email": "verify@seqrlabs.com",
            "password": "Verify1234!",
            "name": "Lochan",
            "org_name": "SeQr Labs Test"
        })
        if r.status_code == 400:
            print("   Already registered, logging in...")
            r = await client.post("/api/v1/auth/login", json={
                "email": "verify@seqrlabs.com",
                "password": "Verify1234!"
            })
        assert r.status_code == 200
        token = r.json()["access_token"]
        print(f"   Token: {token[:20]}...")

        headers = {"Authorization": f"Bearer {token}"}

        print("3. Create asset...")
        r = await client.post("/api/v1/assets",
            headers=headers,
            json={
                "type": "domain",
                "name": "Zerodha",
                "identifier": "zerodha.com",
                "data_sensitivity": "confidential"
            }
        )
        assert r.status_code == 200
        asset_id = r.json()["id"]
        print(f"   Asset ID: {asset_id}")

        print("4. Trigger scan...")
        r = await client.post(
            f"/api/v1/assets/{asset_id}/scan",
            headers=headers,
            timeout=60.0,
        )
        assert r.status_code == 200
        scan_id = r.json()["scan_id"]
        returned_status = r.json()["status"]
        print(f"   Scan ID: {scan_id}  (immediate status: {returned_status})")

        print("5. Poll scan status...")
        for attempt in range(10):
            await asyncio.sleep(2)
            r = await client.get(
                f"/api/v1/scans/{scan_id}",
                headers=headers
            )
            status = r.json()["status"]
            print(f"   Attempt {attempt+1}: {status}")
            if status in ["complete", "failed"]:
                break

        print("6. Final scan result...")
        r = await client.get(
            f"/api/v1/scans/{scan_id}",
            headers=headers
        )
        result = r.json()
        print(f"   Status:           {result['status']}")
        print(f"   Components found: {result.get('components_found', 0)}")
        print(f"   Vulnerable:       {result.get('vulnerable_found', 0)}")
        if result.get("error_message"):
            print(f"   Error:            {result['error_message']}")

        print("7. List assets...")
        r = await client.get("/api/v1/assets", headers=headers)
        assert r.status_code == 200
        print(f"   Assets in org: {len(r.json())}")

        print("8. Create API key...")
        r = await client.post("/api/v1/auth/api-keys",
            headers=headers,
            json={"name": "Test CI Key",
                  "scopes": ["scan:read", "scan:write"]}
        )
        assert r.status_code == 200
        key = r.json()["key"]
        assert key.startswith("sq_live_")
        print(f"   Key: {key[:15]}...")

        print("\nAll checks passed [OK]")


asyncio.run(main())

#!/usr/bin/env python3
"""
Quick test script to verify rate limiting is working on newly protected endpoints.
"""

import asyncio
import aiohttp
import time

async def test_rate_limiting():
    """Test rate limiting on critical endpoints."""
    base_url = "http://localhost:8000"
    
    # Test endpoints that should have rate limiting
    test_endpoints = [
        {
            "url": f"{base_url}/items/upload_image/",
            "method": "POST",
            "limit": "10 per hour",
            "description": "File upload endpoint"
        },
        {
            "url": f"{base_url}/users/me/",
            "method": "PUT", 
            "limit": "5 per minute",
            "description": "Profile update endpoint"
        }
    ]
    
    print("🔒 Rate Limiting Test Suite")
    print("=" * 50)
    
    for endpoint in test_endpoints:
        print(f"\n📝 Testing: {endpoint['description']}")
        print(f"   URL: {endpoint['url']}")
        print(f"   Limit: {endpoint['limit']}")
        print(f"   Method: {endpoint['method']}")
        
        # Make rapid requests to trigger rate limiting
        async with aiohttp.ClientSession() as session:
            responses = []
            
            # Make multiple rapid requests
            for i in range(3):
                try:
                    if endpoint['method'] == 'POST':
                        # For file upload, send empty form data
                        data = aiohttp.FormData()
                        data.add_field('file', b'test', filename='test.jpg', content_type='image/jpeg')
                        async with session.post(endpoint['url'], data=data) as resp:
                            responses.append(resp.status)
                    elif endpoint['method'] == 'PUT':
                        # For profile update, send JSON data (will fail auth but test rate limit)
                        async with session.put(endpoint['url'], json={'name': 'test'}) as resp:
                            responses.append(resp.status)
                    
                except Exception as e:
                    responses.append(f"Error: {e}")
                
                # Small delay between requests
                await asyncio.sleep(0.1)
            
            print(f"   📊 Response codes: {responses}")
            
            # Check for rate limit response (429)
            has_rate_limit = 429 in responses
            print(f"   ✅ Rate limiting active: {'Yes' if has_rate_limit else 'No (may need auth/longer test)'}")

if __name__ == "__main__":
    print("Note: This test requires the FastAPI server to be running on localhost:8000")
    print("Start the server with: poetry run uvicorn app.main:app --reload")
    print("\nPress Enter to continue or Ctrl+C to cancel...")
    try:
        input()
        asyncio.run(test_rate_limiting())
    except KeyboardInterrupt:
        print("\n🚫 Test cancelled")
import os
import json
import logging
import asyncio
import aiohttp
from datetime import datetime
from tqdm.asyncio import tqdm

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)

JWT_API_URLS = [
    "https://jwt.tsunstudio.pw/v1/auth/saeed",
    "https://t-sun-ff-jwt-api-2.vercel.app/v1/auth/saeed",
    "https://t-sun-ff-jwt-api-3.vercel.app/v1/auth/saeed",
    "https://t-sun-ff-jwt-api-4.vercel.app/v1/auth/saeed"
]

TOKENS_FILE = "tokens.json"
FAILED_ACCOUNTS_FILE = "failed_accounts.txt"

def load_accounts(path="xMaSrY.txt"):
    """Load accounts from file in format uid:password"""
    accs = []
    if not os.path.exists(path):
        print(f"✗ File {path} not found!")
        return accs
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                u, p = line.split(':', 1)
                accs.append((u.strip(), p.strip()))
    return accs

async def fetch_jwt_from_api_async(session, uid, password, api_url, pbar):
    """Fetch JWT token from single API endpoint"""
    api_name = api_url.split('/')[2].replace('www.', '')
    max_retries = 2
    
    for attempt in range(max_retries):
        try:
            params = {"uid": uid, "password": password}
            async with session.get(api_url, params=params, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if "token" in data and data["token"]:
                            pbar.update(1)
                            return {
                                "token": data["token"],
                                "fetched_at": datetime.now().isoformat()
                            }
                    except:
                        pass
                elif response.status == 429:
                    await asyncio.sleep(1 + attempt)
                    continue
        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5)
                continue
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5)
                continue
    
    pbar.update(1)
    return None

async def fetch_all_concurrent():
    """Fetch tokens from all 4 APIs concurrently with progress bars"""
    accounts = load_accounts()
    if not accounts:
        print("✗ No accounts loaded. Exiting.")
        return {}, [], []
    
    print(f"\n{'='*75}")
    print(f"🚀 JWT Token Fetch - Concurrent Mode")
    print(f"📊 Total Accounts: {len(accounts)} | APIs: {len(JWT_API_URLS)} | Parallel: YES")
    print(f"{'='*75}\n")
    
    # Divide accounts among 4 APIs (round-robin)
    api_groups = [[] for _ in range(len(JWT_API_URLS))]
    for idx, account in enumerate(accounts):
        api_groups[idx % len(JWT_API_URLS)].append(account)
    
    # Create async session with connection pooling
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
    timeout = aiohttp.ClientTimeout(total=20)
    
    successful_tokens = {}
    failed_accounts = []
    all_tasks = []
    pbars = []
    
    # Create progress bars for each API
    for api_idx, api_url in enumerate(JWT_API_URLS):
        api_name = api_url.split('/')[2].replace('www.', '')
        count = len(api_groups[api_idx])
        pbar = tqdm(
            total=count, 
            desc=f"API-{api_idx+1} ({api_name})", 
            position=api_idx,
            ncols=80,
            colour='green'
        )
        pbars.append(pbar)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Create tasks for all API/account combinations
        for api_idx, (api_url, accounts_group) in enumerate(zip(JWT_API_URLS, api_groups)):
            for uid, password in accounts_group:
                task = fetch_jwt_from_api_async(session, uid, password, api_url, pbars[api_idx])
                all_tasks.append((task, uid, password, api_idx))
        
        # Run all tasks concurrently
        results = await asyncio.gather(*[t[0] for t in all_tasks], return_exceptions=True)
        
        # Process results
        for (_, uid, password, api_idx), result in zip(all_tasks, results):
            if isinstance(result, dict):
                successful_tokens[uid] = result
            elif result is None:
                failed_accounts.append(f"{uid}:{password}")
    
    # Close progress bars
    for pbar in pbars:
        pbar.close()
    
    tokens_list = list(successful_tokens.values())
    failed_list = list(dict.fromkeys(failed_accounts))
    
    return tokens_list, failed_list, accounts

async def main():
    tokens_list, failed_accounts, all_accounts = await fetch_all_concurrent()
    
    # Save successful tokens
    with open(TOKENS_FILE, 'w', encoding='utf-8') as f:
        json.dump(tokens_list, f, indent=2, ensure_ascii=False)
    
    # Save failed accounts
    if failed_accounts:
        with open(FAILED_ACCOUNTS_FILE, 'w', encoding='utf-8') as f:
            f.write(f"# Failed accounts (Rate limited / Network errors)\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total failed: {len(failed_accounts)}\n\n")
            for uid in sorted(failed_accounts):
                f.write(f"{uid}\n")
    
    # Summary
    print(f"\n{'='*75}")
    print(f"✅ JWT FETCH COMPLETE")
    print(f"{'='*75}")
    print(f"Total Accounts:     {len(all_accounts)}")
    print(f"✓ Successful:       {len(tokens_list)}")
    print(f"✗ Failed (429/err): {len(failed_accounts)}")
    print(f"Success Rate:       {len(tokens_list) * 100 // len(all_accounts)}%")
    print(f"{'='*75}\n")
    
    if len(tokens_list) == 0:
        print("✗ No tokens were fetched! Check your credentials and API status.")
        return 1
    
    print(f"✓ Tokens saved to: {TOKENS_FILE}")
    print(f"✓ Ready to use {len(tokens_list)} tokens with BoT.py\n")
    return 0

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    
    exit_code = asyncio.run(main())
    exit(exit_code)

import os, re, logging, asyncio, requests, blackboxprotobuf, urllib3, argparse, json
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from xH import hdr
import XR_GaY_pb2 as WorkshopSubscribe_pb2
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn
from rich.table import Table
from rich import box

urllib3.disable_warnings(InsecureRequestWarning)

# Avoid static attribute access warnings from linters for protobuf messages
CSSubscribeWorkshopCodeReq = getattr(WorkshopSubscribe_pb2, 'CSSubscribeWorkshopCodeReq', None)
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

TOKENS_FILE = "tokens.json"
accounts = []
tokens = {}
lock = asyncio.Lock()
console = Console()
RECENT_LOG_LIMIT = 10

def account_label(uid):
    uid = str(uid)
    return uid if len(uid) <= 8 else f"{uid[:3]}…{uid[-4:]}"

def build_result_table(rows):
    table = Table(box=box.ROUNDED, expand=True, show_header=True, header_style="bold cyan")
    table.add_column("Account", style="bold white", no_wrap=True)
    table.add_column("Result", style="white")
    for uid, result in rows:
        style = "green" if result == "OK" else "yellow" if result and "NO_JWT" in result else "red"
        table.add_row(account_label(uid), f"[{style}]{result}[/{style}]")
    return table

def build_dashboard(title, progress, logs, summary_text=None, results=None):
    header = Panel(
        f"[bold cyan]{title}[/bold cyan]\n[dim]Live token processing dashboard[/dim]",
        box=box.ROUNDED,
        border_style="bright_blue",
        padding=(1, 2),
    )
    log_panel = Panel(
        "\n".join(logs[-RECENT_LOG_LIMIT:]) if logs else "[dim]Waiting for activity...[/dim]",
        title="Live Logs",
        box=box.ROUNDED,
        border_style="bright_magenta",
        padding=(1, 2),
    )
    footer = summary_text or "[dim]Preparing...[/dim]"
    parts = [header, progress, log_panel, Panel(footer, box=box.ROUNDED, border_style="bright_green")]
    if results:
        parts.append(Panel(results, title="Results", box=box.ROUNDED, border_style="bright_cyan", padding=(0, 1)))
    return Group(*parts)

def load_accounts(path="xMaSrY.txt"):
    accs = []
    if not os.path.exists(path): return accs
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if ':' in line: u, p = line.split(':', 1)
            elif '|' in line: u, p = line.split('|', 1)
            else: continue
            accs.append((u.strip(), p.strip()))
    return accs

def enc_req(code):
    m_cls = CSSubscribeWorkshopCodeReq
    if not m_cls:
        raise ImportError('CSSubscribeWorkshopCodeReq not found in protobuf module')
    m = m_cls()
    m.slot_id = 1; m.subscription_source = 26; m.language = 'ar'; m.workshop_code = code
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(m.SerializeToString(), 16))

def send_req(jwt, code):
    try:
        r = requests.post("https://clientbp.ggpolarbear.com/SubscribeWorkshopCode",
                          headers=hdr(jwt), data=enc_req(code), verify=False, timeout=20)
        data = r.content
        if not data: return None
        dec = None
        if len(data) % 16 == 0:
            try: dec = unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(data), 16)
            except: pass
        final = dec if dec else data
        for i in range(15):
            try:
                d, _ = blackboxprotobuf.decode_message(final[i:])
                cnt = d.get('46', {}).get('4') if '46' in d else None
                return cnt if cnt is not None else "OK"
            except: continue
        return "ERR"
    except Exception as e:
        return "429" if "429" in str(e) else "ERR"

def load_tokens_from_file(path=TOKENS_FILE):
    """Load precomputed JWT tokens from JSON file"""
    if not os.path.exists(path):
        logger.error(f"Tokens file {path} not found! Run jwt_fetcher.py first.")
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            token_list = json.load(f)
        if not isinstance(token_list, list):
            raise ValueError("tokens.json must contain a JSON array")
        logger.info(f"Loaded {len(token_list)} tokens from {path}")
        return token_list
    except Exception as e:
        logger.error(f"Error loading tokens: {e}")
        return {}

async def load_tokens_async():
    """Load tokens from file asynchronously"""
    global tokens
    token_data = await asyncio.to_thread(load_tokens_from_file)
    async with lock: tokens = token_data
    return len(token_data)

async def refresher():
    """Periodically reload tokens from file (in case jwt_fetcher.py is run again)"""
    while True:
        try:
            await asyncio.sleep(60 * 60)  # Check every hour
            await load_tokens_async()
        except Exception as e:
            logger.error(f"Refresher task error: {e}")
            await asyncio.sleep(60)

async def proc(u, token_value, code):
    if not token_value:
        return u, "NO_JWT"
    res = await asyncio.to_thread(send_req, token_value, code)
    return u, res

def clean_code(s):
    s = s.strip().upper()
    # Accept both raw codes and prefixed forms like #FREEFIREXXXXXXXX.
    s = re.sub(r'^#?FREEFIRE', '', s)
    return s.strip()

def extract_codes(text):
    parts = re.split(r'[,\s]+', text)
    codes = []
    for p in parts:
        c = clean_code(p)
        if c and len(c) >= 4: codes.append(c)
    return list(dict.fromkeys(codes))

async def process_codes(codes):
    if not codes:
        console.print(Panel("No valid codes.", box=box.ROUNDED, border_style="red"))
        return
    if not accounts:
        console.print(Panel("No accounts.", box=box.ROUNDED, border_style="red"))
        return
    if not tokens:
        console.print(Panel("No tokens loaded.", box=box.ROUNDED, border_style="red"))
        return
    if len(tokens) < len(accounts):
        console.print(Panel(f"Warning: only {len(tokens)} token(s) for {len(accounts)} account(s). Extra accounts will be skipped.", box=box.ROUNDED, border_style="yellow"))

    paired_accounts = list(zip(accounts, tokens))
    overall_progress = Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="bright_green", finished_style="green"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        expand=True,
    )

    logs = [f"[bold cyan]Loaded[/bold cyan] {len(tokens)} token(s) for [bold]{len(accounts)}[/bold] account(s)."]
    summary_text = f"[bold green]Ready[/bold green] - processing {len(codes)} code(s) against {len(paired_accounts)} usable account(s)."

    with Live(build_dashboard("JWT Dashboard", overall_progress, logs, summary_text), console=console, refresh_per_second=12, transient=False) as live:
        total_task = overall_progress.add_task("Overall", total=len(codes) * max(len(paired_accounts), 1))
        final_rows = []
        for code_index, code in enumerate(codes, 1):
            code_task = overall_progress.add_task(f"Code {code_index}/{len(codes)}", total=len(paired_accounts))
            logs.append(f"[bold blue]Starting[/bold blue] code [bold white]{code}[/bold white]")
            live.update(build_dashboard("JWT Dashboard", overall_progress, logs, summary_text))

            tasks = [asyncio.create_task(proc(u, token_item.get("token"), code)) for (u, _), token_item in paired_accounts]
            for future in asyncio.as_completed(tasks):
                uid, result = await future
                label = account_label(uid)
                style = "green" if result == "OK" else "yellow" if result == "NO_JWT" else "red"
                logs.append(f"[bold]{label}[/bold] -> [{style}]{result}[/{style}]")
                final_rows.append((uid, result))
                overall_progress.advance(total_task, 1)
                overall_progress.advance(code_task, 1)
                live.update(build_dashboard("JWT Dashboard", overall_progress, logs, summary_text))

            overall_progress.remove_task(code_task)

        result_table = build_result_table(final_rows[-min(len(final_rows), 20):]) if final_rows else None
        finished_text = f"[bold green]Completed[/bold green] - {len(final_rows)} result(s) rendered."
        live.update(build_dashboard("JWT Dashboard", overall_progress, logs, finished_text, result_table))

async def refresh_and_run(initial_codes=None):
    global accounts
    accounts = load_accounts()
    if not accounts:
        logger.error("No accounts found!")
        return 1
    
    success = await load_tokens_async()
    if success == 0:
        logger.error(f"No tokens loaded from {TOKENS_FILE}. Run jwt_fetcher.py first.")
        return 1
    logger.info(f"Successfully loaded {success} token(s).")
    asyncio.create_task(refresher())
    logger.info("CLI ready.")

    if initial_codes:
        await process_codes(initial_codes)
        return 0

    while True:
        try:
            raw = input("\nEnter map code(s) or press Enter to quit: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw:
            break
        await process_codes(extract_codes(raw))
    return 0

def main():
    parser = argparse.ArgumentParser(description="Terminal script for processing map codes.")
    parser.add_argument("codes", nargs="*", help="Map codes separated by spaces")
    args = parser.parse_args()
    initial_codes = extract_codes(" ".join(args.codes)) if args.codes else []
    try:
        exit_code = asyncio.run(refresh_and_run(initial_codes))
    except KeyboardInterrupt:
        logger.info("Interrupted by user (Ctrl+C). Shutting down gracefully...")
        exit_code = 0
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
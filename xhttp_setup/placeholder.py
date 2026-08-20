def neutral_placeholder(domain: str) -> str:
    safe_domain = (
        domain.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>{safe_domain}</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
    body {{ min-height: 100vh; margin: 0; display: grid; place-items: center;
            background: #f3f5f7; color: #16202a; }}
    main {{ width: min(34rem, calc(100% - 3rem)); padding: 2.5rem;
            background: white; border: 1px solid #dfe5eb; border-radius: 1rem;
            box-shadow: 0 1rem 3rem #25313d18; }}
    h1 {{ margin-top: 0; font-size: 1.65rem; }}
    p {{ line-height: 1.6; color: #536170; }}
    a {{ display: inline-block; margin-top: .75rem; padding: .75rem 1rem;
         color: white; background: #1769aa; border-radius: .55rem;
         text-decoration: none; }}
    small {{ display: block; margin-top: 1.5rem; color: #7b8792; }}
    @media (prefers-color-scheme: dark) {{
      body {{ background: #10161c; color: #e7edf3; }}
      main {{ background: #172029; border-color: #293743; }}
      p, small {{ color: #aab7c3; }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>Сайт работает</h1>
    <p>Это независимая техническая страница домена {safe_domain}.</p>
    <a href="https://rufox.ru/" rel="noopener noreferrer">Открыть RuFox</a>
    <small>Эта страница не является сайтом RuFox и не копирует его содержимое.</small>
  </main>
</body>
</html>
"""

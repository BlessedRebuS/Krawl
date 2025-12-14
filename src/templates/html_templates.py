#!/usr/bin/env python3

"""
HTML templates for the deception server.
Edit these templates to customize the appearance of fake pages.
"""


def login_form() -> str:
    """Generate fake login page"""
    return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
        h2 { margin-top: 0; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Admin Login</h2>
        <form action="/admin/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""


def login_error() -> str:
    """Generate fake login error page"""
    return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login Failed</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
        h2 { margin-top: 0; color: #333; }
        .error { color: #d63301; background: #ffebe8; border: 1px solid #d63301; padding: 12px; margin-bottom: 20px; border-radius: 4px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        a { color: #007bff; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Admin Login</h2>
        <div class="error"><strong>ERROR:</strong> Invalid username or password.</div>
        <form action="/admin/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p style="margin-top: 20px; text-align: center;"><a href="/forgot-password">Forgot your password?</a></p>
    </div>
</body>
</html>"""


def wordpress() -> str:
    """Generate fake WordPress page"""
    return """<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>My Blog &#8211; Just another WordPress site</title>
    <link rel='dns-prefetch' href='//s.w.org' />
    <link rel='stylesheet' id='wp-block-library-css' href='/wp-includes/css/dist/block-library/style.min.css' type='text/css' media='all' />
    <link rel='stylesheet' id='twentytwentythree-style-css' href='/wp-content/themes/twentytwentythree/style.css' type='text/css' media='all' />
    <link rel='https://api.w.org/' href='/wp-json/' />
    <meta name="generator" content="WordPress 6.4.2" />
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; margin: 0; padding: 0; background: #fff; }
        .site-header { background: #23282d; color: white; padding: 20px; border-bottom: 4px solid #0073aa; }
        .site-header h1 { margin: 0; font-size: 28px; }
        .site-header p { margin: 5px 0 0; color: #d0d0d0; }
        .site-content { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .entry { background: #fff; margin-bottom: 40px; padding: 30px; border: 1px solid #ddd; border-radius: 4px; }
        .entry-title { font-size: 32px; margin-top: 0; color: #23282d; }
        .entry-meta { color: #666; font-size: 14px; margin-bottom: 20px; }
        .entry-content { line-height: 1.8; color: #444; }
        .site-footer { background: #f7f7f7; padding: 20px; text-align: center; color: #666; border-top: 1px solid #ddd; margin-top: 60px; }
        a { color: #0073aa; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body class="home blog wp-embed-responsive">
<div id="page" class="site">
    <header id="masthead" class="site-header">
        <div class="site-branding">
            <h1 class="site-title">My Blog</h1>
            <p class="site-description">Just another WordPress site</p>
        </div>
    </header>

    <div id="content" class="site-content">
        <article id="post-1" class="entry">
            <header class="entry-header">
                <h2 class="entry-title">Hello world!</h2>
                <div class="entry-meta">
                    <span class="posted-on">Posted on <time datetime="2024-12-01">December 1, 2024</time></span>
                    <span class="byline"> by <span class="author">admin</span></span>
                </div>
            </header>
            <div class="entry-content">
                <p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
            </div>
        </article>

        <article id="post-2" class="entry">
            <header class="entry-header">
                <h2 class="entry-title">About This Site</h2>
                <div class="entry-meta">
                    <span class="posted-on">Posted on <time datetime="2024-11-28">November 28, 2024</time></span>
                    <span class="byline"> by <span class="author">admin</span></span>
                </div>
            </header>
            <div class="entry-content">
                <p>This is a sample page. You can use it to write about your site, yourself, or anything else you'd like.</p>
            </div>
        </article>
    </div>

    <footer id="colophon" class="site-footer">
        <div class="site-info">
            Proudly powered by <a href="https://wordpress.org/">WordPress</a>
        </div>
    </footer>
</div>
<script type='text/javascript' src='/wp-includes/js/wp-embed.min.js'></script>
</body>
</html>"""


def phpmyadmin() -> str:
    """Generate fake phpMyAdmin page"""
    return """<!DOCTYPE html>
<html>
<head>
    <title>phpMyAdmin</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; background: #f0f0f0; }
        .header { background: #2979ff; color: white; padding: 10px 20px; }
        .login { background: white; width: 400px; margin: 100px auto; padding: 30px; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        input { width: 100%; padding: 8px; margin: 8px 0; border: 1px solid #ddd; }
        button { padding: 10px 20px; background: #2979ff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header"><h1>phpMyAdmin</h1></div>
    <div class="login">
        <h2>MySQL Server Login</h2>
        <form action="/phpMyAdmin/index.php" method="post">
            <input type="text" name="pma_username" placeholder="Username">
            <input type="password" name="pma_password" placeholder="Password">
            <button type="submit">Go</button>
        </form>
    </div>
</body>
</html>"""


def robots_txt() -> str:
    """Generate juicy robots.txt"""
    return """User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /backup/
Disallow: /config/
Disallow: /database/
Disallow: /private/
Disallow: /uploads/
Disallow: /wp-admin/
Disallow: /phpMyAdmin/
Disallow: /admin/login.php
Disallow: /api/v1/users
Disallow: /api/v2/secrets
Disallow: /.env
Disallow: /credentials.txt
Disallow: /passwords.txt
Disallow: /.git/
Disallow: /backup.sql
Disallow: /db_backup.sql
"""


def directory_listing(path: str, dirs: list, files: list) -> str:
    """Generate fake directory listing"""
    html = f"""<!DOCTYPE html>
<html>
<head><title>Index of {path}</title>
<style>
    body {{ font-family: monospace; background: #fff; padding: 20px; }}
    h1 {{ border-bottom: 1px solid #ccc; padding-bottom: 10px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; padding: 10px; background: #f0f0f0; }}
    td {{ padding: 8px; border-bottom: 1px solid #eee; }}
    a {{ color: #0066cc; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>Index of {path}</h1>
<table>
<tr><th>Name</th><th>Last Modified</th><th>Size</th></tr>
<tr><td><a href="../">Parent Directory</a></td><td>-</td><td>-</td></tr>
"""
    
    for d in dirs:
        html += f'<tr><td><a href="{d}">{d}</a></td><td>2024-12-01 10:30</td><td>-</td></tr>\n'
    
    for f, size in files:
        html += f'<tr><td><a href="{f}">{f}</a></td><td>2024-12-01 14:22</td><td>{size}</td></tr>\n'
    
    html += '</table></body></html>'
    return html

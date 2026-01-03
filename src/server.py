#!/usr/bin/env python3

"""
Main server module for the deception honeypot.
Run this file to start the server.
"""

import sys
from http.server import HTTPServer

from config import get_config
from tracker import AccessTracker
from handler import Handler
from logger import initialize_logging, get_app_logger, get_access_logger, get_credential_logger
from database import initialize_database


def print_usage():
    """Print usage information"""
    print(f'Usage: {sys.argv[0]} [FILE]\n')
    print('FILE is file containing a list of webpage names to serve, one per line.')
    print('If no file is provided, random links will be generated.\n')
    print('Configuration:')
    print('  Configuration is loaded from a YAML file (default: config.yaml)')
    print('  Set CONFIG_LOCATION environment variable to use a different file.\n')
    print('  Example config.yaml structure:')
    print('    server:')
    print('      port: 5000')
    print('      delay: 100')
    print('      timezone: null  # or "America/New_York"')
    print('    links:')
    print('      min_length: 5')
    print('      max_length: 15')
    print('      min_per_page: 10')
    print('      max_per_page: 15')
    print('    canary:')
    print('      token_url: null')
    print('      token_tries: 10')
    print('    dashboard:')
    print('      secret_path: null  # auto-generated if not set')
    print('    database:')
    print('      path: "data/krawl.db"')
    print('      retention_days: 30')
    print('    behavior:')
    print('      probability_error_codes: 0')


def main():
    """Main entry point for the deception server"""
    if '-h' in sys.argv or '--help' in sys.argv:
        print_usage()
        exit(0)

    config = get_config()

    # Get timezone configuration
    tz = config.get_timezone()

    # Initialize logging with timezone
    initialize_logging(timezone=tz)
    app_logger = get_app_logger()
    access_logger = get_access_logger()
    credential_logger = get_credential_logger()

    # Initialize database for persistent storage
    try:
        initialize_database(config.database_path)
        app_logger.info(f'Database initialized at: {config.database_path}')
    except Exception as e:
        app_logger.warning(f'Database initialization failed: {e}. Continuing with in-memory only.')

    tracker = AccessTracker(timezone=tz)

    Handler.config = config
    Handler.tracker = tracker
    Handler.counter = config.canary_token_tries
    Handler.app_logger = app_logger
    Handler.access_logger = access_logger
    Handler.credential_logger = credential_logger

    if len(sys.argv) == 2:
        try:
            with open(sys.argv[1], 'r') as f:
                Handler.webpages = f.readlines()

            if not Handler.webpages:
                app_logger.warning('The file provided was empty. Using randomly generated links.')
                Handler.webpages = None
        except IOError:
            app_logger.warning("Can't read input file. Using randomly generated links.")

    try:
        app_logger.info(f'Starting deception server on port {config.port}...')
        app_logger.info(f'Timezone configured: {tz.key}')
        app_logger.info(f'Dashboard available at: {config.dashboard_secret_path}')
        if config.canary_token_url:
            app_logger.info(f'Canary token will appear after {config.canary_token_tries} tries')
        else:
            app_logger.info('No canary token configured (set CANARY_TOKEN_URL to enable)')

        server = HTTPServer(('0.0.0.0', config.port), Handler)
        app_logger.info('Server started. Use <Ctrl-C> to stop.')
        server.serve_forever()
    except KeyboardInterrupt:
        app_logger.info('Stopping server...')
        server.socket.close()
        app_logger.info('Server stopped')
    except Exception as e:
        app_logger.error(f'Error starting HTTP server on port {config.port}: {e}')
        app_logger.error(f'Make sure you are root, if needed, and that port {config.port} is open.')
        exit(1)


if __name__ == '__main__':
    main()

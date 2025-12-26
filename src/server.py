#!/usr/bin/env python3

"""
Main server module for the deception honeypot.
Run this file to start the server.
"""

import sys
from http.server import HTTPServer

from config import Config
from tracker import AccessTracker
from handler import Handler


def print_usage():
    """Print usage information"""
    print(f'Usage: {sys.argv[0]} [FILE]\n')
    print('FILE is file containing a list of webpage names to serve, one per line.')
    print('If no file is provided, random links will be generated.\n')
    print('Environment Variables:')
    print('  PORT                  - Server port (default: 5000)')
    print('  DELAY                 - Response delay in ms (default: 100)')
    print('  LINKS_MIN_LENGTH      - Min link length (default: 5)')
    print('  LINKS_MAX_LENGTH      - Max link length (default: 15)')
    print('  LINKS_MIN_PER_PAGE    - Min links per page (default: 10)')
    print('  LINKS_MAX_PER_PAGE    - Max links per page (default: 15)')
    print('  MAX_COUNTER           - Max counter value (default: 10)')
    print('  CANARY_TOKEN_URL      - Canary token URL to display')
    print('  CANARY_TOKEN_TRIES    - Number of tries before showing token (default: 10)')
    print('  DASHBOARD_SECRET_PATH - Secret path for dashboard (auto-generated if not set)')
    print('  PROBABILITY_ERROR_CODES - Probability (0-100) to return HTTP error codes (default: 0)')
    print('  CHAR_SPACE            - Characters for random links')
    print('  SERVER_HEADER         - HTTP Server header for deception (default: Apache/2.2.22 (Ubuntu))')


def main():
    """Main entry point for the deception server"""
    if '-h' in sys.argv or '--help' in sys.argv:
        print_usage()
        exit(0)

    config = Config.from_env()
    
    tracker = AccessTracker()
    
    Handler.config = config
    Handler.tracker = tracker
    Handler.counter = config.canary_token_tries

    if len(sys.argv) == 2:
        try:
            with open(sys.argv[1], 'r') as f:
                Handler.webpages = f.readlines()

            if not Handler.webpages:
                print('The file provided was empty. Using randomly generated links.')
                Handler.webpages = None
        except IOError:
            print('Can\'t read input file. Using randomly generated links.')

    try:
        print(f'Starting deception server on port {config.port}...')
        print(f'Dashboard available at: {config.dashboard_secret_path}')
        if config.canary_token_url:
            print(f'Canary token will appear after {config.canary_token_tries} tries')
        else:
            print('No canary token configured (set CANARY_TOKEN_URL to enable)')
        
        server = HTTPServer(('0.0.0.0', config.port), Handler)
        print('Server started. Use <Ctrl-C> to stop.')
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopping server...')
        server.socket.close()
        print('Server stopped')
    except Exception as e:
        print(f'Error starting HTTP server on port {config.port}: {e}')
        print(f'Make sure you are root, if needed, and that port {config.port} is open.')
        exit(1)


if __name__ == '__main__':
    main()

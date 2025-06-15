import argparse
import logging
import json
import requests
import pandas as pd
import sys  # For graceful exit

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Analyze API endpoints for vulnerabilities.')
    parser.add_argument('api_definition', help='Path to OpenAPI/Swagger definition file (JSON) or URL to live API endpoint.')
    parser.add_argument('--output', '-o', help='Output file to save the analysis report (CSV).  Defaults to console output.', default=None)
    parser.add_argument('--auth_header', help='Authorization header to use (e.g., "Bearer <token>")', default=None)
    parser.add_argument('--rate_limit_threshold', type=int, default=100, help='Threshold for rate limiting analysis.  Defaults to 100 requests/minute.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output (debug logging).')

    return parser.parse_args()


def load_api_definition(api_definition_path):
    """
    Loads the API definition from a file or URL.
    Handles both local files and remote URLs.
    Returns a JSON object representing the API definition.
    Raises exceptions if loading fails.
    """
    try:
        if api_definition_path.startswith('http://') or api_definition_path.startswith('https://'):
            # Load from URL
            logging.info(f"Loading API definition from URL: {api_definition_path}")
            response = requests.get(api_definition_path)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            api_definition = response.json()
        else:
            # Load from file
            logging.info(f"Loading API definition from file: {api_definition_path}")
            with open(api_definition_path, 'r') as f:
                api_definition = json.load(f)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error loading API definition from URL: {e}")
        raise  # Re-raise to be caught in main()
    except FileNotFoundError:
        logging.error(f"API definition file not found: {api_definition_path}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in API definition file: {api_definition_path}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading the API definition: {e}")
        raise

    return api_definition


def analyze_api(api_definition, auth_header=None, rate_limit_threshold=100):
    """
    Analyzes the API definition for potential vulnerabilities.
    Returns a Pandas DataFrame containing the analysis results.
    """

    results = []

    # Basic checks (can be expanded significantly)
    if 'components' not in api_definition or 'securitySchemes' not in api_definition['components']:
        logging.warning("No security schemes defined. API might lack authentication.")
        results.append({'Check': 'Security Schemes', 'Result': 'No security schemes defined', 'Severity': 'High', 'Details': 'API might lack authentication.  Investigate each endpoint.'})


    # Check for rate limiting (very basic example - can be improved)
    # This is a simplified check based on description keywords.  More robust checks would require dynamic testing.
    paths = api_definition.get('paths', {})
    for path, path_item in paths.items():
        for method, operation in path_item.items():
            description = operation.get('description', '').lower()
            if "rate limit" not in description and "rate-limit" not in description:
                # Potentially missing rate limiting
                results.append({
                    'Check': 'Rate Limiting',
                    'Result': f'Potential missing rate limiting on endpoint: {method.upper()} {path}',
                    'Severity': 'Medium',
                    'Details': f'The {method.upper()} method at {path} does not appear to have explicit rate limiting configured based on its description.  Further investigation is required.'
                })


    # Check for authorization headers (very basic example - can be improved)
    for path, path_item in paths.items():
        for method, operation in path_item.items():
            security = operation.get('security', [])
            if not security:
                results.append({
                    'Check': 'Authentication',
                    'Result': f'Missing authentication on endpoint: {method.upper()} {path}',
                    'Severity': 'High',
                    'Details': f'The {method.upper()} method at {path} does not require authentication.  This could lead to unauthorized access.'
                })


    df = pd.DataFrame(results)
    return df


def main():
    """
    Main function to orchestrate the API analysis process.
    """
    try:
        args = setup_argparse()

        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)  # Set root logger to DEBUG

        logging.debug(f"Command-line arguments: {args}")

        # Input validation (example)
        if args.rate_limit_threshold < 0:
            raise ValueError("Rate limit threshold must be a non-negative integer.")

        api_definition = load_api_definition(args.api_definition)
        analysis_results = analyze_api(api_definition, args.auth_header, args.rate_limit_threshold)

        if analysis_results.empty:
            print("No potential vulnerabilities found.")
            logging.info("No potential vulnerabilities found.")
        else:
            if args.output:
                # Output to CSV file
                analysis_results.to_csv(args.output, index=False)
                print(f"Analysis results saved to: {args.output}")
                logging.info(f"Analysis results saved to: {args.output}")
            else:
                # Output to console
                print(analysis_results.to_string())
                logging.info("Analysis results printed to console.")

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        print(f"Error: {e}")
        sys.exit(1)  # Exit with an error code
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        print(f"Error: {e}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        print(f"Error: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error: {e}")
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Use exception to print stack trace
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
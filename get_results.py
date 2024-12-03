import re
import csv
from collections import defaultdict

# Threshold for flagging IPs with suspicious activity (more than 10 failed login attempts)
FAILED_LOGIN_THRESHOLD = 10

def parse_log(file_path):
    # Initialize default dictionaries to store counts for IPs, endpoints, and failed logins
    ip_request = defaultdict(int)  # Tracks the count of requests for each IP
    endpoint_requests = defaultdict(int)  # Tracks the count of requests for each endpoint
    failed_logins = defaultdict(int)  # Tracks the count of failed login attempts for each IP

    # Regular expressions to extract specific details from each log line
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # Matches IPv4 addresses in the log
    endpoint_pattern = r'"(?:GET|POST) (\S+)'  # Captures the endpoint path after "GET" or "POST"
    failed_login_pattern = r'HTTP/1.1" 401'  # Identifies lines with failed login attempts (HTTP status 401)

    # Open and read the log file line by line
    with open(file_path, 'r') as log_file:
        for line in log_file:  # Loop through each line of the log file
            # Extract and count the IP address from the log line
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)  # Extract matched IP address
                ip_request[ip] += 1  # Increment the count for this IP

            # Extract and count the endpoint from the log line
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)  # Extract matched endpoint
                endpoint_requests[endpoint] += 1  # Increment the count for this endpoint

            # Check for failed login attempts in the log line
            if re.search(failed_login_pattern, line):  # Match HTTP 401 status code
                failed_msg = re.search(r'Invalid Credentials', line)  # Additional check for "Invalid Credentials"
                if failed_msg:
                    failed_logins[ip] += 1  # Increment the failed login count for this IP

    # Return the populated dictionaries
    return ip_request, endpoint_requests, failed_logins

def save_results_to_csv(ip_requests, endpoint_requests, failed_logins):
    # Open a CSV file to save the results
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        # Define the headers for the CSV file
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()  # Write the header row

        # Write sorted IP requests to the CSV file
        sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ip_requests:
            writer.writerow({'IP Address': ip, 'Request Count': count})  # Write each IP and its count

        writer.writerow({})  # Add an empty row for separation

        # Determine and write the most accessed endpoint
        most_accessed_endpoint = max(endpoint_requests, key=endpoint_requests.get)  # Find the endpoint with max requests
        writer.writerow({
            'IP Address': 'Most Accessed Endpoint',
            'Request Count': f"{most_accessed_endpoint} Accessed {endpoint_requests[most_accessed_endpoint]} times"
        })

        writer.writerow({})  # Add another empty row for separation

        # Write information about suspicious activity (failed logins)
        writer.writerow({'IP Address': 'Suspicious Activity', 'Request Count': ''})
        for ip, failed_count in failed_logins.items():
            if failed_count > FAILED_LOGIN_THRESHOLD:  # Check if failed attempts exceed the threshold
                writer.writerow({'IP Address': ip, 'Request Count': f"Failed Login Attempts: {failed_count}"})

def main():
    # Path to the log file
    log_file_path = '/sample.log'
    # Parse the log file and retrieve counts for IPs, endpoints, and failed logins
    ip_requests, endpoint_requests, failed_logins = parse_log(log_file_path)
    # Save the results to a CSV file
    save_results_to_csv(ip_requests, endpoint_requests, failed_logins)

if __name__ == "__main__":
    main()

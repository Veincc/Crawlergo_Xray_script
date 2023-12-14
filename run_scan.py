import subprocess
import time
import threading
import psutil
import argparse

def run_xray_and_crawl(target_file, output_file):
    # Set timeout for overall execution
    timeout_seconds = 15

    # Xray run command
    xray_cmd = './xray webscan'
    xray_cmd += ' --listen 127.0.0.1:7777'
    xray_cmd += ' --plugins sqldet,xss'
    xray_cmd += f' --json-output {output_file}'

    processing_output_received = False
    last_output_time = time.time()

    def read_output(process):
        nonlocal processing_output_received, last_output_time

        while True:
            # Read and print Xray process output
            output = process.stdout.readline()
            if not output:
                break

            print(output, end="")
            last_output_time = time.time()

            # Set flag when "processing" is found in the output
            if "processing" in output.lower():
                processing_output_received = True

    print('################ Run Xray ################')
    # Start Xray process
    process = subprocess.Popen(xray_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=True)

    try:
        # Start a thread to continuously read Xray process output
        output_thread = threading.Thread(target=read_output, args=(process,))
        output_thread.start()

        # Loop through the target URLs and run Crawlergo for each
        with open(target_file, 'r') as urls_file:
            for url in urls_file:
                print(f'################ Run crawl for URL: {url} ################')
                crawl_cmd = f'./crawlergo -t 10 -f smart --fuzz-path --push-to-proxy http://127.0.0.1:7777/ --push-pool-max 10 --output-mode json {url}'
                rsp_crawl = subprocess.Popen(crawl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                rsp_crawl.communicate()
                print(f'################ Crawl Done for URL: {url} ################')

        # Wait for Xray processing to complete and timeout
        while not processing_output_received or time.time() - last_output_time <= timeout_seconds:
            time.sleep(1)

        # Terminate Xray process and its children
        parent_process = psutil.Process(process.pid)
        for child in parent_process.children(recursive=True):
            child.terminate()
        time.sleep(2)

        # Ensure all child processes are terminated
        for child in parent_process.children(recursive=True):
            try:
                child.terminate()
                child.wait(timeout=2)
            except psutil.NoSuchProcess:
                pass

    except KeyboardInterrupt:
        pass

    finally:
        # Close Xray process stdout, wait for process to finish, and print return code
        process.stdout.close()
        process.wait()
        print("################ Xray scan Done ################")
        print("Return Code:", process.returncode)

# Set up the command line argument parser
parser = argparse.ArgumentParser(description='Run Xray and Crawlergo for web scanning and crawling.')
parser.add_argument('-f', '--file', required=True, help='Path to the file containing target URLs for crawling')
parser.add_argument('-o', '--output', required=True, help='Output JSON file path')

# Parse command line arguments
args = parser.parse_args()

# Call the function and pass in the arguments
run_xray_and_crawl(args.file, args.output)

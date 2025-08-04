import urllib.request
import os
import sys
import shutil
import json
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
try:
	SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
	TARGET_DIR = os.path.realpath(
		os.path.join(SCRIPT_PATH, os.path.pardir, "dnsbl.d")
	)
	LISTS_CONF = os.path.join(SCRIPT_PATH, "lists.json")
	LISTS_CONF_SAMPLE = os.path.join(SCRIPT_PATH, "lists.sample.json")
except Exception as e:
	logger.error(f"Error setting up paths: {e}")
	sys.exit(1)

def ensure_directory_exists(dir_path):
	"""Ensure target directory exists, create if not"""
	try:
		Path(dir_path).mkdir(parents=True, exist_ok=True)
	except Exception as e:
		logger.error(f"Failed to create directory {dir_path}: {e}")
		sys.exit(1)

def download_file(url, destination):
	"""Download a file with proper error handling"""
	temp_path = f"/tmp/{os.path.basename(destination)}.tmp"
	
	try:
		logger.info(f"Downloading {url} to {destination}")
		
		# Download to temporary file
		urllib.request.urlretrieve(url, temp_path)
		
		# Move to final destination
		shutil.move(temp_path, destination)
		logger.info(f"Successfully downloaded {destination}")

	except Exception as e:
		logger.error(f"Unexpected error downloading {url}: {e}")
		if os.path.exists(temp_path):
			os.unlink(temp_path)
		raise

def main():
	# Check if configuration exists
	if not os.path.isfile(LISTS_CONF):
		logger.error(f"{LISTS_CONF} does not exist, please configure it"
			f" properly. (See {LISTS_CONF_SAMPLE})")
		sys.exit(1)

	# Open and read the JSON file
	with open(LISTS_CONF, "r") as file:
		try:
			LISTS_JSON = dict(json.load(file))
		except json.decoder.JSONDecodeError as e:
			logger.error(
				f"Please configure your {LISTS_CONF} file correctly "
				f"(must be JSON Parse-able Data, see {LISTS_CONF_SAMPLE})."
			)
			raise e

	if not LISTS_JSON:
		logger.error("No lists have been configured")
		sys.exit(0)

	# Ensure target directory exists
	ensure_directory_exists(TARGET_DIR)
	
	# Process each list
	for list_name, list_url in LISTS_JSON.items():
		dest_path = os.path.join(TARGET_DIR, list_name)
		try:
			download_file(list_url, dest_path)
		except Exception as e:
			logger.error(f"Skipping {list_name} due to error: {e}")
			continue

if __name__ == "__main__":
	main()

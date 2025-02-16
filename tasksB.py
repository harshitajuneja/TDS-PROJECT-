import os
import json
import requests
import sqlite3
import duckdb
import markdown
from PIL import Image
from pathlib import Path
import logging
from typing import Optional, Tuple, List, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Custom exception for security violations"""
    pass

def B12(filepath: str) -> bool:
    """
    Security check to ensure file operations are restricted to /data directory.
    Args:
        filepath (str): Path to validate
    Returns:
        bool: True if path starts with /data, False otherwise
    """
    if not filepath:
        logger.warning("Empty filepath provided")
        return False
    
    try:
        # Normalize path to prevent directory traversal
        normalized_path = os.path.normpath(filepath)
        if not normalized_path.startswith('/data'):
            logger.warning(f"Access attempt outside /data directory: {filepath}")
            return False
        return True
    except Exception as e:
        logger.error(f"Security check failed for path {filepath}: {str(e)}")
        return False

def create_directory_if_not_exists(filepath: str) -> None:
    """
    Safely create directory for a file if it doesn't exist
    Args:
        filepath (str): Path to the file
    """
    if not B12(filepath):
        raise SecurityError(f"Cannot create directory outside /data: {filepath}")
    directory = os.path.dirname(filepath)
    if directory:
        os.makedirs(directory, exist_ok=True)

def B3(url: str, save_path: str) -> None:
    """
    Fetch data from an API and save it securely.
    Args:
        url (str): URL to fetch data from
        save_path (str): Path to save the data (must be under /data)
    """
    try:
        # Security check
        if not B12(save_path):
            raise SecurityError(f"Invalid save path: {save_path}")

        # Fetch data with timeout
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        # Create directory if needed
        create_directory_if_not_exists(save_path)
        
        # Save the response
        with open(save_path, 'w', encoding='utf-8') as file:
            file.write(response.text)
            
        logger.info(f"Successfully fetched and saved data from {url} to {save_path}")
        
    except requests.RequestException as e:
        logger.error(f"Failed to fetch data from {url}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error in B3: {str(e)}")
        raise

def B5(db_path: str, query: str, output_filename: str) -> List[Any]:
    """
    Run SQL query on SQLite or DuckDB database and save results.
    Args:
        db_path (str): Path to database file (must be under /data)
        query (str): SQL query to execute
        output_filename (str): Path to save results (must be under /data)
    Returns:
        list: Query results
    """
    try:
        # Security checks
        if not B12(db_path):
            raise SecurityError(f"Invalid database path: {db_path}")
        if not B12(output_filename):
            raise SecurityError(f"Invalid output path: {output_filename}")

        # Choose database type based on extension
        is_sqlite = db_path.endswith('.db')
        conn = sqlite3.connect(db_path) if is_sqlite else duckdb.connect(db_path)
        
        try:
            cur = conn.cursor()
            cur.execute(query)
            result = cur.fetchall()
            
            create_directory_if_not_exists(output_filename)
            
            with open(output_filename, 'w', encoding='utf-8') as file:
                file.write(str(result))
            
            logger.info(f"Successfully executed query and saved results to {output_filename}")
            return result
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Error in B5: {str(e)}")
        raise

def B6(url: str, output_filename: str) -> None:
    """
    Scrape data from a website and save it securely.
    Args:
        url (str): URL to scrape
        output_filename (str): Path to save scraped data (must be under /data)
    """
    try:
        # Security check
        if not B12(output_filename):
            raise SecurityError(f"Invalid output path: {output_filename}")

        # Fetch webpage with timeout
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        create_directory_if_not_exists(output_filename)
        
        with open(output_filename, 'w', encoding='utf-8') as file:
            file.write(response.text)
            
        logger.info(f"Successfully scraped data from {url} to {output_filename}")
        
    except requests.RequestException as e:
        logger.error(f"Failed to scrape {url}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error in B6: {str(e)}")
        raise

def B7(image_path: str, output_path: str, resize: Optional[Tuple[int, int]] = None) -> None:
    """
    Process an image (resize/compress) securely.
    Args:
        image_path (str): Path to source image (must be under /data)
        output_path (str): Path to save processed image (must be under /data)
        resize (tuple, optional): New dimensions as (width, height)
    """
    try:
        # Security checks
        if not B12(image_path):
            raise SecurityError(f"Invalid image path: {image_path}")
        if not B12(output_path):
            raise SecurityError(f"Invalid output path: {output_path}")

        with Image.open(image_path) as img:
            if resize:
                img = img.resize(resize)
            
            create_directory_if_not_exists(output_path)
            
            # Save with optimization
            img.save(output_path, optimize=True)
            
        logger.info(f"Successfully processed image from {image_path} to {output_path}")
        
    except Exception as e:
        logger.error(f"Error in B7: {str(e)}")
        raise

def B9(md_path: str, output_path: str) -> None:
    """
    Convert Markdown to HTML securely.
    Args:
        md_path (str): Path to source Markdown file (must be under /data)
        output_path (str): Path to save HTML file (must be under /data)
    """
    try:
        # Security checks
        if not B12(md_path):
            raise SecurityError(f"Invalid markdown path: {md_path}")
        if not B12(output_path):
            raise SecurityError(f"Invalid output path: {output_path}")

        # Read markdown content
        with open(md_path, 'r', encoding='utf-8') as file:
            md_content = file.read()
        
        # Convert to HTML
        html_content = markdown.markdown(md_content)
        
        create_directory_if_not_exists(output_path)
        
        # Save HTML
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(html_content)
            
        logger.info(f"Successfully converted markdown from {md_path} to {output_path}")
        
    except Exception as e:
        logger.error(f"Error in B9: {str(e)}")
        raise

def B10(csv_path: str, filter_column: str, filter_value: str) -> Dict[str, Any]:
    """
    Filter CSV and return results as JSON.
    Args:
        csv_path (str): Path to CSV file (must be under /data)
        filter_column (str): Column name to filter on
        filter_value (str): Value to filter for
    Returns:
        dict: Filtered data as JSON
    """
    try:
        if not B12(csv_path):
            raise SecurityError(f"Invalid CSV path: {csv_path}")
        
        import pandas as pd
        df = pd.read_csv(csv_path)
        filtered = df[df[filter_column] == filter_value]
        return filtered.to_dict(orient='records')
    except Exception as e:
        logger.error(f"Error in B10: {str(e)}")
        raise

# Example usage
if __name__ == "_main_":
    try:
        # Test data directory
        os.makedirs('/data/test', exist_ok=True)
        
        # Test B3
        print("\nTesting B3 - API Fetch:")
        B3("https://jsonplaceholder.typicode.com/todos/1", "/data/test/api_result.json")
        
        # Test B5
        print("\nTesting B5 - SQL Query:")
        test_db = "/data/test/test.db"
        conn = sqlite3.connect(test_db)
        conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO test VALUES (1, 'test')")
        conn.commit()
        conn.close()
        B5(test_db, "SELECT * FROM test", "/data/test/query_result.txt")
        
        # Test B6
        print("\nTesting B6 - Web Scraping:")
        B6("https://example.com", "/data/test/scraped.txt")
        
        # Test B7
        print("\nTesting B7 - Image Processing:")
        # Create test image
        img = Image.new('RGB', (100, 100), color='red')
        img.save("/data/test/test.jpg")
        B7("/data/test/test.jpg", "/data/test/resized.jpg", (50, 50))
        
        # Test B9
        print("\nTesting B9 - Markdown Conversion:")
        with open("/data/test/test.md", "w") as f:
            f.write("# Test\nThis is a test")
        B9("/data/test/test.md", "/data/test/test.html")
        
        print("\nAll tests completed successfully!")
        
    except Exception as e:
        print(f"Test failed: {str(e)}")

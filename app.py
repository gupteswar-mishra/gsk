from flask import Flask, request, jsonify
from google.cloud import storage, bigquery
from datetime import datetime
import re

app = Flask(__name__)
storage_client = storage.Client()
bq_client = bigquery.Client()

# BigQuery configuration
PROJECT_ID = bq_client.project  # Auto-detected from environment
DATASET_ID = "network_logs"
TABLE_ID = "error_disable_events"
FULL_TABLE_ID = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"

# Regex patterns
ERR_DISABLE_PATTERN = re.compile(
    r"%PM-4-ERR_DISABLE:\s*(\w+)\s*error detected on\s*(\S+)",
    re.IGNORECASE
)
RECOVER_PATTERN = re.compile(
    r"%PM-4-ERR_RECOVER:\s*Attempting to recover from\s*(\w+)\s*err-disable state on\s*(\S+)",
    re.IGNORECASE
)

# Pattern to extract device name (adjust based on your log format)
DEVICE_PATTERN = re.compile(
    r"(\w+[-\w]*)\s*%PM-4",
    re.IGNORECASE
)

def preprocess_text(raw_log):
    """
    Basic text preprocessing with None/empty check
    """
    if not raw_log:
        return ""
    
    text = raw_log.lower()
    text = text.strip()
    return text

def extract_device_name(raw_log):
    """
    Extract device name from log message
    """
    if not raw_log:
        return "unknown"
    
    device_match = DEVICE_PATTERN.search(raw_log)
    if device_match:
        return device_match.group(1)
    return "unknown"

def extract_fields(preprocessed_text, raw_log):
    """
    Extract reason and interface from log message
    """
    if not preprocessed_text:
        return None
        
    err_match = ERR_DISABLE_PATTERN.search(preprocessed_text)
    rec_match = RECOVER_PATTERN.search(preprocessed_text)
    
    device_name = extract_device_name(raw_log)
    
    if err_match:
        return {
            "event_type": "ERR_DISABLE",
            "device_name": device_name,
            "reason": err_match.group(1),
            "interface": err_match.group(2)
        }
    if rec_match:
        return {
            "event_type": "ERR_RECOVER",
            "device_name": device_name,
            "reason": rec_match.group(1),
            "interface": rec_match.group(2)
        }
    return None

def insert_to_bigquery(records):
    """
    Insert processed records into BigQuery
    """
    if not records:
        return {"inserted": 0, "errors": []}
    
    # Prepare rows for BigQuery
    rows_to_insert = []
    current_time = datetime.utcnow().isoformat()
    
    for record in records:
        row = {
            "event_timestamp": record.get("event_timestamp"),
            "device_name": record.get("device_name"),
            "interface": record.get("interface"),
            "error_reason": record.get("error_reason"),
            "raw_message": record.get("raw_message"),
            "ingestion_time": current_time
        }
        rows_to_insert.append(row)
    
    # Insert into BigQuery
    errors = bq_client.insert_rows_json(FULL_TABLE_ID, rows_to_insert)
    
    if errors:
        return {"inserted": 0, "errors": errors}
    else:
        return {"inserted": len(rows_to_insert), "errors": []}

@app.route("/process", methods=["POST"])
def process():
    """
    Main endpoint to process logs from GCS and load into BigQuery
    """
    try:
        data = request.json
        bucket_name = data.get("bucket")
        file_name = data.get("file")
        
        if not bucket_name or not file_name:
            return jsonify({"error": "bucket and file required"}), 400
        
        # Download file from GCS
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(file_name)
        
        if not blob.exists():
            return jsonify({"error": f"File {file_name} not found in bucket {bucket_name}"}), 404
        
        content = blob.download_as_text()
        
        # Process logs
        processed_records = []
        skipped_lines = 0
        
        for line in content.splitlines():
            if not line or not line.strip():
                skipped_lines += 1
                continue
                
            cleaned = preprocess_text(line)
            extracted = extract_fields(cleaned, line)
            
            if extracted:
                # Prepare record for BigQuery
                bq_record = {
                    "event_timestamp": datetime.utcnow().isoformat(),  # Use current time or extract from log
                    "device_name": extracted.get("device_name", "unknown"),
                    "interface": extracted.get("interface", "unknown"),
                    "error_reason": extracted.get("reason", "unknown"),
                    "raw_message": line,
                }
                processed_records.append(bq_record)
        
        # Insert into BigQuery
        insert_result = insert_to_bigquery(processed_records)
        
        if insert_result["errors"]:
            return jsonify({
                "status": "partial_success",
                "processed_lines": len(content.splitlines()),
                "skipped_lines": skipped_lines,
                "matched_records": len(processed_records),
                "inserted_records": insert_result["inserted"],
                "bigquery_errors": insert_result["errors"]
            }), 207
        
        return jsonify({
            "status": "success",
            "processed_lines": len(content.splitlines()),
            "skipped_lines": skipped_lines,
            "matched_records": len(processed_records),
            "inserted_records": insert_result["inserted"],
            "bucket": bucket_name,
            "file": file_name
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "error_type": type(e).__name__
        }), 500

@app.route("/health", methods=["GET"])
@app.route("/", methods=["GET"])
def health():
    """
    Health check endpoint
    """
    try:
        # Check BigQuery connectivity
        bq_client.query("SELECT 1").result()
        return jsonify({
            "status": "healthy",
            "service": "log-preprocessor",
            "bigquery": "connected",
            "table": FULL_TABLE_ID
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

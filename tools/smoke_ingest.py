"""End-to-end ingestion smoke test.

Uploads a sample flow JSON (Firehose envelope) to the S3 landing bucket under
``flows/``, then polls Snowflake until the Snowpipe lands it in
RAW_FLOW_LANDING and the flatten task populates FLOW_FEATURES.

Usage:
    python tools/smoke_ingest.py [--wait 120] [--sample .cache/smoke_flows.json]
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

from deploy_cloud import REPO_ROOT, build_session, load_dotenv

load_dotenv()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait', type=int, default=120)
    parser.add_argument('--sample', type=Path, default=REPO_ROOT / '.cache' / 'smoke_flows.json')
    args = parser.parse_args(argv)

    bucket = os.environ.get('S3_FLOW_BUCKET')
    if not bucket:
        raise SystemExit('S3_FLOW_BUCKET not set in .env')

    import boto3

    s3 = boto3.client('s3', region_name=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))
    key = f'flows/smoke_{int(time.time())}.json'
    s3.put_object(Bucket=bucket, Key=key, Body=args.sample.read_bytes())
    print(f'Uploaded s3://{bucket}/{key} (prefix flows/ -> SQS -> pipe)')

    session = build_session()
    try:
        deadline = time.time() + args.wait
        landing = 0
        features = 0
        while time.time() < deadline:
            landing = session.sql('SELECT COUNT(*) FROM RAW_FLOW_LANDING').collect()[0][0]
            features = session.sql('SELECT COUNT(*) FROM FLOW_FEATURES').collect()[0][0]
            status = session.sql("SELECT SYSTEM$PIPE_STATUS('CORE.PIPE_RAW_FLOW')").collect()[0][0]
            if isinstance(status, str):
                status = json.loads(status)
            print(f"  t-{int(deadline - time.time()):3d}s raw={landing} features={features} "
                  f"pipe_state={status.get('executionState')} pending={status.get('pendingFileCount')}")
            if features >= 2:
                print('PASS: ready row(s) -> RAW_FLOW_LANDING -> FLOW_FEATURES (flatten applied)')
                return 0
            time.sleep(15)
        print(f'FAIL: raw={landing} features={features} (timeout {args.wait}s). See COPY_HISTORY/pipe status.')
        return 1
    finally:
        session.close()


if __name__ == '__main__':
    raise SystemExit(main())
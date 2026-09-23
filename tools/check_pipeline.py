"""Print phase-1 pipeline state: pipe, stage auth, and pipe status."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

from deploy_cloud import build_session, load_dotenv

load_dotenv()
s = build_session()
try:
    rows = s.sql("SHOW PIPES LIKE 'PIPE_RAW_FLOW'").collect()
    for r in rows:
        d = r.as_dict()
        print('pipe                :', d.get('name'))
        print('pipe state          :', d.get('state'))
        print('notification_channel:', d.get('notification_channel'))

    rows = s.sql('DESCRIBE STAGE CORE.S3_FLOW_STAGE').collect()
    for r in rows:
        d = r.as_dict()
        print('stage url           :', d.get('url'))
        print('storage_integration:', d.get('storage_integration'))
        creds = d.get('credentials')
        print('credentials_present:', bool(creds))

    rows = s.sql("SELECT SYSTEM$PIPE_STATUS('CORE.PIPE_RAW_FLOW')").collect()
    print('pipe status         :', str(rows[0].as_dict())[:300])
finally:
    s.close()
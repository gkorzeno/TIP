#!/usr/bin/env python3
"""
Threat Intelligence Platform (TIP)
A system for collecting, analyzing, and managing threat intelligence data
"""

import os
import sys
import json
import time
import uuid
import logging
import argparse
import threading
import sqlite3
import hashlib
from datetime import datetime
from urllib import error as urllib_error
from urllib import request as urllib_request
from functools import wraps

try:
    import requests
except ImportError:
    requests = None

try:
    from werkzeug.security import generate_password_hash, check_password_hash
except ImportError:
    def generate_password_hash(password):
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)
        return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"

    def check_password_hash(stored_hash, password):
        try:
            algorithm, salt_hex, digest_hex = stored_hash.split('$', 2)
        except ValueError:
            return False
        if algorithm != 'pbkdf2_sha256':
            return False
        digest = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            bytes.fromhex(salt_hex),
            600000
        )
        return digest.hex() == digest_hex


class SimpleHTTPResponse:
    """Minimal response wrapper matching the subset of requests used by this file."""
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = body.decode('utf-8', errors='replace')

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP request failed with status {self.status_code}")

    def json(self):
        return json.loads(self.text)


def http_get(url, headers=None, timeout=30):
    """HTTP GET using requests when available, otherwise urllib."""
    if requests is not None:
        return requests.get(url, headers=headers, timeout=timeout)

    req = urllib_request.Request(url, headers=headers or {}, method='GET')
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            return SimpleHTTPResponse(resp.status, resp.read())
    except urllib_error.HTTPError as exc:
        return SimpleHTTPResponse(exc.code, exc.read())


def http_post(url, headers=None, json_data=None, timeout=30):
    """HTTP POST using requests when available, otherwise urllib."""
    if requests is not None:
        return requests.post(url, headers=headers, json=json_data, timeout=timeout)

    body = None
    merged_headers = dict(headers or {})
    if json_data is not None:
        body = json.dumps(json_data).encode('utf-8')
        merged_headers.setdefault('Content-Type', 'application/json')

    req = urllib_request.Request(url, data=body, headers=merged_headers, method='POST')
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            return SimpleHTTPResponse(resp.status, resp.read())
    except urllib_error.HTTPError as exc:
        return SimpleHTTPResponse(exc.code, exc.read())

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('tip.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class ThreatIntelPlatform:
    """Main Threat Intelligence Platform class"""
    def __init__(self, config):
        self.config = config
        self.indicators = {}
        self.feeds = {}
        self.running = True
        
        # Initialize database
        self.init_database()
        
        # Load feeds
        self.load_feeds()
        
        # Load existing indicators
        self.load_indicators()
        
        # Initialize API integrations
        self.init_integrations()
        
        # Start feed update threads
        if self.config.get('enable_feed_updates', True):
            self.start_feed_updates()
    
    def init_database(self):
        """Initialize SQLite database for storing threat intelligence data"""
        db_path = self.config.get('db_path', 'tip.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create indicators table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id TEXT PRIMARY KEY,
            type TEXT,
            value TEXT,
            source TEXT,
            first_seen TEXT,
            last_seen TEXT,
            confidence INTEGER,
            severity TEXT,
            tags TEXT,
            context TEXT,
            status TEXT
        )
        ''')
        
        # Create feeds table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS feeds (
            id TEXT PRIMARY KEY,
            name TEXT,
            url TEXT,
            type TEXT,
            auth_type TEXT,
            auth_data TEXT,
            interval INTEGER,
            last_update TEXT,
            enabled INTEGER,
            config TEXT
        )
        ''')
        
        # Create users table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT,
            role TEXT,
            api_key TEXT,
            last_login TEXT
        )
        ''')
        
        # Create alerts table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            severity TEXT,
            status TEXT,
            created TEXT,
            updated TEXT,
            assigned_to TEXT,
            indicators TEXT,
            source TEXT
        )
        ''')
        
        # Create rules table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            condition TEXT,
            action TEXT,
            enabled INTEGER,
            created TEXT,
            updated TEXT
        )
        ''')
        
        # Create integrations table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            name TEXT,
            type TEXT,
            config TEXT,
            enabled INTEGER,
            last_sync TEXT
        )
        ''')
        
        # Create default admin user if none exists
        self.cursor.execute("SELECT COUNT(*) FROM users")
        if self.cursor.fetchone()[0] == 0:
            user_id = str(uuid.uuid4())
            username = "admin"
            password = self.config.get('initial_admin_password') or uuid.uuid4().hex[:16]
            password_hash = generate_password_hash(password)
            api_key = hashlib.sha256(os.urandom(32)).hexdigest()
            
            self.cursor.execute('''
                INSERT INTO users (id, username, password_hash, email, role, api_key)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_id, username, password_hash, "admin@example.com", "admin", api_key
            ))
            
            logging.info(f"Created default admin user (username: {username})")
            print(f"Created default admin user (username: {username}, password: {password})")
        
        self.conn.commit()
    
    def load_feeds(self):
        """Load configured threat intelligence feeds"""
        self.cursor.execute("SELECT * FROM feeds")
        for row in self.cursor.fetchall():
            feed_id, name, url, feed_type, auth_type, auth_data, interval, last_update, enabled, config = row
            
            self.feeds[feed_id] = {
                'id': feed_id,
                'name': name,
                'url': url,
                'type': feed_type,
                'auth_type': auth_type,
                'auth_data': auth_data,
                'interval': interval,
                'last_update': last_update,
                'enabled': bool(enabled),
                'config': json.loads(config) if config else {}
            }
        
        logging.info(f"Loaded {len(self.feeds)} intelligence feeds")
        
        # Add default feeds if none exist
        if not self.feeds:
            self.add_default_feeds()
    
    def add_default_feeds(self):
        """Add default threat intelligence feeds"""
        default_feeds = [
            {
                'name': 'AlienVault OTX',
                'url': 'https://otx.alienvault.com/api/v1/indicators/export',
                'type': 'otx',
                'auth_type': 'api_key',
                'auth_data': '',  # User needs to add their API key
                'interval': 3600,  # 1 hour
                'config': {'pulse_ids': []}
            },
            {
                'name': 'MISP Feed',
                'url': 'https://example.com/misp/events/restSearch',
                'type': 'misp',
                'auth_type': 'api_key',
                'auth_data': '',  # User needs to add their API key
                'interval': 3600,  # 1 hour
                'config': {'org_id': ''}
            },
            {
                'name': 'PhishTank',
                'url': 'http://data.phishtank.com/data/online-valid.json',
                'type': 'phishtank',
                'auth_type': 'none',
                'auth_data': '',
                'interval': 86400,  # 24 hours
                'config': {}
            },
            {
                'name': 'Abuse.ch URLhaus',
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'type': 'urlhaus',
                'auth_type': 'none',
                'auth_data': '',
                'interval': 43200,  # 12 hours
                'config': {}
            }
        ]
        
        for feed in default_feeds:
            feed_id = str(uuid.uuid4())
            current_time = datetime.now().isoformat()
            
            self.cursor.execute('''
                INSERT INTO feeds (id, name, url, type, auth_type, auth_data, interval, last_update, enabled, config)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                feed_id, feed['name'], feed['url'], feed['type'], feed['auth_type'], 
                feed['auth_data'], feed['interval'], current_time, 1, json.dumps(feed['config'])
            ))
            
            self.feeds[feed_id] = {
                'id': feed_id,
                'name': feed['name'],
                'url': feed['url'],
                'type': feed['type'],
                'auth_type': feed['auth_type'],
                'auth_data': feed['auth_data'],
                'interval': feed['interval'],
                'last_update': current_time,
                'enabled': True,
                'config': feed['config']
            }
        
        self.conn.commit()
        logging.info(f"Added {len(default_feeds)} default intelligence feeds")
    
    def load_indicators(self):
        """Load existing indicators from database"""
        self.cursor.execute("SELECT * FROM indicators")
        count = 0
        
        for row in self.cursor.fetchall():
            id, type, value, source, first_seen, last_seen, confidence, severity, tags, context, status = row
            
            self.indicators[id] = {
                'id': id,
                'type': type,
                'value': value,
                'source': source,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'confidence': confidence,
                'severity': severity,
                'tags': json.loads(tags) if tags else [],
                'context': json.loads(context) if context else {},
                'status': status
            }
            count += 1
        
        logging.info(f"Loaded {count} indicators from database")
    
    def init_integrations(self):
        """Initialize API integrations with other security tools"""
        self.cursor.execute("SELECT * FROM integrations")
        for row in self.cursor.fetchall():
            integration_id, name, integration_type, config, enabled, last_sync = row
            
            if enabled:
                config_data = json.loads(config)
                
                # Initialize different types of integrations
                if integration_type == 'siem':
                    # SIEM integration (e.g., Splunk, ELK)
                    logging.info(f"Initializing SIEM integration: {name}")
                    # Implementation would depend on the specific SIEM
                
                elif integration_type == 'firewall':
                    # Firewall integration (e.g., Palo Alto, Cisco)
                    logging.info(f"Initializing firewall integration: {name}")
                    # Implementation would depend on the specific firewall
                
                elif integration_type == 'edr':
                    # EDR integration (e.g., CrowdStrike, SentinelOne)
                    logging.info(f"Initializing EDR integration: {name}")
                    # Implementation would depend on the specific EDR
    
    def start_feed_updates(self):
        """Start threads to periodically update feeds"""
        for feed_id, feed in self.feeds.items():
            if feed['enabled']:
                thread = threading.Thread(target=self.feed_update_thread, args=(feed_id,))
                thread.daemon = True
                thread.start()
                logging.info(f"Started update thread for feed: {feed['name']}")
    
    def feed_update_thread(self, feed_id):
        """Thread to periodically update a specific feed"""
        while self.running:
            try:
                feed = self.feeds.get(feed_id)
                if not feed or not feed['enabled']:
                    break
                
                logging.info(f"Updating feed: {feed['name']}")
                
                # Update the feed based on its type
                if feed['type'] == 'otx':
                    self.update_otx_feed(feed)
                elif feed['type'] == 'misp':
                    self.update_misp_feed(feed)
                elif feed['type'] == 'phishtank':
                    self.update_phishtank_feed(feed)
                elif feed['type'] == 'urlhaus':
                    self.update_urlhaus_feed(feed)
                else:
                    logging.warning(f"Unknown feed type: {feed['type']}")
                
                # Update last update time
                current_time = datetime.now().isoformat()
                feed['last_update'] = current_time
                
                self.cursor.execute(
                    "UPDATE feeds SET last_update = ? WHERE id = ?",
                    (current_time, feed_id)
                )
                self.conn.commit()
                
            except Exception as e:
                logging.error(f"Error updating feed {feed_id}: {str(e)}")
            
            # Sleep until next update
            time.sleep(feed['interval'])
    
    def update_otx_feed(self, feed):
        """Update AlienVault OTX feed"""
        if not feed['auth_data']:
            logging.warning(f"No API key provided for OTX feed: {feed['name']}")
            return
        
        headers = {'X-OTX-API-KEY': feed['auth_data']}
        
        try:
            # Get pulses
            if not feed['config'].get('pulse_ids'):
                # Get recent pulses if none specified
                response = http_get(
                    'https://otx.alienvault.com/api/v1/pulses/subscribed',
                    headers=headers
                )
                response.raise_for_status()
                
                pulses = response.json().get('results', [])
                pulse_ids = [pulse['id'] for pulse in pulses]
            else:
                pulse_ids = feed['config']['pulse_ids']
            
            # Process each pulse
            for pulse_id in pulse_ids:
                response = http_get(
                    f'https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators',
                    headers=headers
                )
                response.raise_for_status()
                
                indicators = response.json().get('results', [])
                
                for indicator in indicators:
                    self.add_indicator({
                        'type': indicator['type'],
                        'value': indicator['indicator'],
                        'source': f"OTX:{feed['name']}",
                        'confidence': 70,  # Default confidence
                        'severity': 'medium',  # Default severity
                        'tags': indicator.get('tags', []),
                        'context': {
                            'pulse_id': pulse_id,
                            'created': indicator.get('created'),
                            'description': indicator.get('description', '')
                        }
                    })
            
            logging.info(f"Updated OTX feed: {feed['name']}")
            
        except Exception as e:
            logging.error(f"Error updating OTX feed {feed['name']}: {str(e)}")
    
    def update_misp_feed(self, feed):
        """Update MISP feed"""
        if not feed['auth_data']:
            logging.warning(f"No API key provided for MISP feed: {feed['name']}")
            return
        
        headers = {
            'Authorization': feed['auth_data'],
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        try:
            # Get recent events
            data = {
                'returnFormat': 'json',
                'limit': 100,
                'published': True
            }
            
            if feed['config'].get('org_id'):
                data['org'] = feed['config']['org_id']
            
            response = http_post(
                feed['url'],
                headers=headers,
                json_data=data
            )
            response.raise_for_status()
            
            events = response.json()
            
            for event in events:
                event_id = event.get('Event', {}).get('id')
                
                if not event_id:
                    continue
                
                # Get attributes for this event
                for attribute in event.get('Event', {}).get('Attribute', []):
                    if attribute.get('type') in ['ip-src', 'ip-dst', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email']:
                        self.add_indicator({
                            'type': attribute['type'],
                            'value': attribute['value'],
                            'source': f"MISP:{feed['name']}",
                            'confidence': 70,  # Default confidence
                            'severity': 'medium',  # Default severity
                            'tags': [tag['name'] for tag in attribute.get('Tag', [])],
                            'context': {
                                'event_id': event_id,
                                'created': attribute.get('timestamp'),
                                'comment': attribute.get('comment', '')
                            }
                        })
            
            logging.info(f"Updated MISP feed: {feed['name']}")
            
        except Exception as e:
            logging.error(f"Error updating MISP feed {feed['name']}: {str(e)}")
    
    def update_phishtank_feed(self, feed):
        """Update PhishTank feed"""
        try:
            response = http_get(feed['url'])
            response.raise_for_status()
            
            phish_sites = response.json()
            
            for site in phish_sites:
                self.add_indicator({
                    'type': 'url',
                    'value': site.get('url'),
                    'source': f"PhishTank:{feed['name']}",
                    'confidence': 80,  # Higher confidence for PhishTank
                    'severity': 'high',  # Phishing is typically high severity
                    'tags': ['phishing'],
                    'context': {
                        'phish_id': site.get('phish_id'),
                        'verified': site.get('verified'),
                        'verification_time': site.get('verification_time')
                    }
                })
            
            logging.info(f"Updated PhishTank feed: {feed['name']}")
            
        except Exception as e:
            logging.error(f"Error updating PhishTank feed {feed['name']}: {str(e)}")
    
    def update_urlhaus_feed(self, feed):
        """Update URLhaus feed"""
        try:
            response = http_get(feed['url'])
            response.raise_for_status()
            
            # URLhaus provides a CSV file
            lines = response.text.split('\n')
            
            # Skip header and comment lines
            data_lines = [line for line in lines if line and not line.startswith('#')]
            
            for line in data_lines:
                parts = line.split(',')
                if len(parts) >= 3:
                    url = parts[2].strip('"')
                    
                    if url:
                        self.add_indicator({
                            'type': 'url',
                            'value': url,
                            'source': f"URLhaus:{feed['name']}",
                            'confidence': 75,
                            'severity': 'high',
                            'tags': ['malware'],
                            'context': {
                                'status': parts[1] if len(parts) > 1 else '',
                                'date_added': parts[0] if len(parts) > 0 else ''
                            }
                        })
            
            logging.info(f"Updated URLhaus feed: {feed['name']}")
            
        except Exception as e:
            logging.error(f"Error updating URLhaus feed {feed['name']}: {str(e)}")
    
    def add_indicator(self, indicator_data):
        """Add or update an indicator in the database"""
        indicator_type = indicator_data.get('type')
        indicator_value = indicator_data.get('value')
        
        if not indicator_type or not indicator_value:
            return False
        
        # Check if this indicator already exists
        existing_id = None
        for id, indicator in self.indicators.items():
            if indicator['type'] == indicator_type and indicator['value'] == indicator_value:
                existing_id = id
                break
        
        current_time = datetime.now().isoformat()
        
        if existing_id:
            # Update existing indicator
            indicator = self.indicators[existing_id]
            indicator['last_seen'] = current_time
            indicator['source'] = indicator_data.get('source', indicator['source'])
            indicator['confidence'] = indicator_data.get('confidence', indicator['confidence'])
            indicator['severity'] = indicator_data.get('severity', indicator['severity'])
            
            # Merge tags
            new_tags = indicator_data.get('tags', [])
            if new_tags:
                indicator['tags'] = list(set(indicator['tags'] + new_tags))
            
            # Update context
            new_context = indicator_data.get('context', {})
            if new_context:
                indicator['context'].update(new_context)
            
            # Update in database
            self.cursor.execute('''
                UPDATE indicators 
                SET last_seen = ?, source = ?, confidence = ?, severity = ?, tags = ?, context = ?
                WHERE id = ?
            ''', (
                indicator['last_seen'], indicator['source'], indicator['confidence'],
                indicator['severity'], json.dumps(indicator['tags']), json.dumps(indicator['context']),
                existing_id
            ))
            
        else:
            # Create new indicator
            indicator_id = str(uuid.uuid4())
            
            indicator = {
                'id': indicator_id,
                'type': indicator_type,
                'value': indicator_value,
                'source': indicator_data.get('source', 'manual'),
                'first_seen': current_time,
                'last_seen': current_time,
                'confidence': indicator_data.get('confidence', 50),
                'severity': indicator_data.get('severity', 'medium'),
                'tags': indicator_data.get('tags', []),
                'context': indicator_data.get('context', {}),
                'status': 'active'
            }
            
            # Insert into database
            self.cursor.execute('''
                INSERT INTO indicators 
                (id, type, value, source, first_seen, last_seen, confidence, severity, tags, context, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                indicator['id'], indicator['type'], indicator['value'], indicator['source'],
                indicator['first_seen'], indicator['last_seen'], indicator['confidence'],
                indicator['severity'], json.dumps(indicator['tags']), json.dumps(indicator['context']),
                indicator['status']
            ))
            
            self.indicators[indicator_id] = indicator
        
        self.conn.commit()
        
        # Check if this indicator matches any rules
        self.check_indicator_rules(indicator)
        
        return True
    
    def check_indicator_rules(self, indicator):
        """Check if an indicator matches any rules and take appropriate actions"""
        self.cursor.execute("SELECT * FROM rules WHERE enabled = 1")
        
        for row in self.cursor.fetchall():
            rule_id, name, description, condition, action, enabled, created, updated = row
            
            # Parse and evaluate the condition
            try:
                # Simple condition format: field:operator:value
                # Example: type:equals:ip-src
                parts = condition.split(':')
                if len(parts) >= 3:
                    field = parts[0]
                    operator = parts[1]
                    value = ':'.join(parts[2:])  # Rejoin in case value contains colons
                    
                    field_value = indicator.get(field)
                    
                    if field == 'tags' and isinstance(field_value, list):
                        # Special handling for tags
                        if operator == 'contains':
                            if value in field_value:
                                self.execute_rule_action(rule_id, name, action, indicator)
                        elif operator == 'not_contains':
                            if value not in field_value:
                                self.execute_rule_action(rule_id, name, action, indicator)
                    else:
                        # Standard field comparison
                        if operator == 'equals' and str(field_value) == value:
                            self.execute_rule_action(rule_id, name, action, indicator)
                        elif operator == 'not_equals' and str(field_value) != value:
                            self.execute_rule_action(rule_id, name, action, indicator)
                        elif operator == 'contains' and value in str(field_value):
                            self.execute_rule_action(rule_id, name, action, indicator)
                        elif operator == 'starts_with' and str(field_value).startswith(value):
                            self.execute_rule_action(rule_id, name, action, indicator)
                        elif operator == 'ends_with' and str(field_value).endswith(value):
                            self.execute_rule_action(rule_id, name, action, indicator)
                        elif operator == 'greater_than' and float(field_value) > float(value):
                            self.execute_rule_action(rule_id, name, action, indicator)
                        elif operator == 'less_than' and float(field_value) < float(value):
                            self.execute_rule_action(rule_id, name, action, indicator)
            
            except Exception as e:
                logging.error(f"Error evaluating rule {rule_id}: {str(e)}")
    
    def execute_rule_action(self, rule_id, rule_name, action, indicator):
        """Execute the action specified by a rule"""
        logging.info(f"Rule '{rule_name}' triggered for indicator: {indicator['type']}:{indicator['value']}")
        
        # Parse action: action_type:parameters
        parts = action.split(':')
        if len(parts) < 2:
            logging.error(f"Invalid action format for rule {rule_id}: {action}")
            return
        
        action_type = parts[0]
        parameters = ':'.join(parts[1:])
        
        if action_type == 'alert':
            # Create an alert
            alert_id = str(uuid.uuid4())
            current_time = datetime.now().isoformat()
            
            self.cursor.execute('''
                INSERT INTO alerts 
                (id, title, description, severity, status, created, updated, indicators, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_id,
                f"Rule '{rule_name}' triggered",
                f"Indicator {indicator['type']}:{indicator['value']} matched rule '{rule_name}'",
                parameters or indicator['severity'],
                'new',
                current_time,
                current_time,
                json.dumps([indicator['id']]),
                f"Rule:{rule_id}"
            ))
            
            self.conn.commit()
            logging.info(f"Created alert {alert_id} from rule {rule_id}")
            
        elif action_type == 'tag':
            # Add a tag to the indicator
            if parameters and parameters not in indicator['tags']:
                indicator['tags'].append(parameters)
                
                self.cursor.execute(
                    "UPDATE indicators SET tags = ? WHERE id = ?",
                    (json.dumps(indicator['tags']), indicator['id'])
                )
                
                self.conn.commit()
                logging.info(f"Added tag '{parameters}' to indicator {indicator['id']}")
                
        elif action_type == 'set_severity':
            # Set the severity of the indicator
            if parameters in ['low', 'medium', 'high', 'critical']:
                indicator['severity'] = parameters
                
                self.cursor.execute(
                    "UPDATE indicators SET severity = ? WHERE id = ?",
                    (parameters, indicator['id'])
                )
                
                self.conn.commit()
                logging.info(f"Set severity of indicator {indicator['id']} to {parameters}")
                
        elif action_type == 'set_confidence':
            # Set the confidence of the indicator
            try:
                confidence = int(parameters)
                if 0 <= confidence <= 100:
                    indicator['confidence'] = confidence
                    
                    self.cursor.execute(
                        "UPDATE indicators SET confidence = ? WHERE id = ?",
                        (confidence, indicator['id'])
                    )
                    
                    self.conn.commit()
                    logging.info(f"Set confidence of indicator {indicator['id']} to {confidence}")
            except ValueError:
                logging.error(f"Invalid confidence value in rule {rule_id}: {parameters}")
                
        elif action_type == 'block':
            # Send block command to integrated security devices
            # This would typically call an integration API
            logging.info(f"Block action triggered for {indicator['type']}:{indicator['value']}")
            
            # Example: if we had a firewall integration
            # self.block_in_firewall(indicator)
            
        elif action_type == 'webhook':
            # Send data to a webhook
            try:
                http_post(
                    parameters,
                    json_data={
                        'rule_id': rule_id,
                        'rule_name': rule_name,
                        'indicator': indicator
                    }
                )
                logging.info(f"Sent webhook for rule {rule_id} to {parameters}")
            except Exception as e:
                logging.error(f"Error sending webhook for rule {rule_id}: {str(e)}")
    
    def search_indicators(self, query):
        """Search for indicators matching the query"""
        results = []
        
        # Parse query parameters
        query_type = query.get('type')
        query_value = query.get('value')
        query_tags = query.get('tags', [])
        query_severity = query.get('severity')
        query_confidence = query.get('confidence')
        query_source = query.get('source')
        
        for indicator_id, indicator in self.indicators.items():
            match = True
            
            if query_type and indicator['type'] != query_type:
                match = False
            
            if query_value and query_value not in indicator['value']:
                match = False
            
            if query_tags:
                for tag in query_tags:
                    if tag not in indicator['tags']:
                        match = False
                        break
            
            if query_severity and indicator['severity'] != query_severity:
                match = False
            
            if query_confidence:
                try:
                    min_confidence = int(query_confidence)
                    if indicator['confidence'] < min_confidence:
                        match = False
                except ValueError:
                    pass
            
            if query_source and query_source not in indicator['source']:
                match = False
            
            if match:
                results.append(indicator)
        
        return results
    
    def get_indicator_stats(self):
        """Get statistics about indicators"""
        stats = {
            'total': len(self.indicators),
            'by_type': {},
            'by_severity': {
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            },
            'by_source': {},
            'recent': 0  # Added in last 24 hours
        }
        
        current_time = datetime.now()
        
        for indicator in self.indicators.values():
            # Count by type
            indicator_type = indicator['type']
            if indicator_type not in stats['by_type']:
                stats['by_type'][indicator_type] = 0
            stats['by_type'][indicator_type] += 1
            
            # Count by severity
            severity = indicator['severity']
            if severity in stats['by_severity']:
                stats['by_severity'][severity] += 1
            
            # Count by source
            source = indicator['source'].split(':')[0] if ':' in indicator['source'] else indicator['source']
            if source not in stats['by_source']:
                stats['by_source'][source] = 0
            stats['by_source'][source] += 1
            
            # Count recent indicators
            try:
                first_seen = datetime.fromisoformat(indicator['first_seen'])
                if (current_time - first_seen).total_seconds() < 86400:  # 24 hours
                    stats['recent'] += 1
            except (ValueError, TypeError):
                pass
        
        return stats
    
    def start_web_server(self):
        """Start the web interface"""
        try:
            from flask import Flask, request, jsonify, redirect, url_for, session
            from flask_cors import CORS
        except ImportError as exc:
            raise RuntimeError(
                "Flask dependencies are required to run the web server. "
                "Install 'flask' and 'flask-cors' to start the UI."
            ) from exc

        app = Flask(__name__)
        app.secret_key = self.config.get('secret_key') or hashlib.sha256(os.urandom(32)).hexdigest()
        CORS(app)

        def login_required(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if 'user_id' not in session:
                    return redirect(url_for('login'))
                return func(*args, **kwargs)
            return wrapper

        def serialize_rows(rows, columns):
            return [dict(zip(columns, row)) for row in rows]

        @app.route('/')
        def index():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            return redirect(url_for('dashboard'))

        @app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '')

                self.cursor.execute(
                    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                    (username,)
                )
                row = self.cursor.fetchone()

                if row and check_password_hash(row[2], password):
                    session['user_id'] = row[0]
                    session['username'] = row[1]
                    session['role'] = row[3]

                    self.cursor.execute(
                        "UPDATE users SET last_login = ? WHERE id = ?",
                        (datetime.now().isoformat(), row[0])
                    )
                    self.conn.commit()
                    return redirect(url_for('dashboard'))

                return """
                <h2>Threat Intelligence Platform Login</h2>
                <p style="color:red;">Invalid username or password</p>
                <form method="post">
                    <label>Username <input name="username" /></label><br><br>
                    <label>Password <input name="password" type="password" /></label><br><br>
                    <button type="submit">Login</button>
                </form>
                """, 401

            return """
            <h2>Threat Intelligence Platform Login</h2>
            <form method="post">
                <label>Username <input name="username" /></label><br><br>
                <label>Password <input name="password" type="password" /></label><br><br>
                <button type="submit">Login</button>
            </form>
            """

        @app.route('/logout')
        def logout():
            session.clear()
            return redirect(url_for('login'))

        @app.route('/dashboard')
        @login_required
        def dashboard():
            stats = self.get_indicator_stats()
            return f"""
            <html>
            <head><title>Threat Intelligence Platform</title></head>
            <body>
                <h1>Threat Intelligence Platform</h1>
                <p>Signed in as {session.get('username')}</p>
                <ul>
                    <li>Total indicators: {stats['total']}</li>
                    <li>Recent indicators: {stats['recent']}</li>
                    <li>Severity counts: {json.dumps(stats['by_severity'])}</li>
                    <li>Sources: {json.dumps(stats['by_source'])}</li>
                </ul>
                <h2>Add Indicator</h2>
                <form method="post" action="/ui/indicators">
                    <label>Type <input name="type" required /></label><br><br>
                    <label>Value <input name="value" required /></label><br><br>
                    <label>Source <input name="source" value="manual" /></label><br><br>
                    <label>Confidence <input name="confidence" type="number" min="0" max="100" value="50" /></label><br><br>
                    <label>Severity
                        <select name="severity">
                            <option value="low">low</option>
                            <option value="medium" selected>medium</option>
                            <option value="high">high</option>
                            <option value="critical">critical</option>
                        </select>
                    </label><br><br>
                    <label>Tags (comma separated) <input name="tags" /></label><br><br>
                    <label>Context JSON <textarea name="context" rows="4" cols="50">{{}}</textarea></label><br><br>
                    <button type="submit">Add Indicator</button>
                </form>
                <h2>Add Rule</h2>
                <form method="post" action="/ui/rules">
                    <label>Name <input name="name" required /></label><br><br>
                    <label>Description <input name="description" /></label><br><br>
                    <label>Condition <input name="condition" placeholder="severity:equals:high" required /></label><br><br>
                    <label>Action <input name="action" placeholder="alert:high" required /></label><br><br>
                    <label>Enabled
                        <select name="enabled">
                            <option value="1" selected>Yes</option>
                            <option value="0">No</option>
                        </select>
                    </label><br><br>
                    <button type="submit">Add Rule</button>
                </form>
                <p>
                    <a href="/api/stats">Stats API</a> |
                    <a href="/api/indicators">Indicators API</a> |
                    <a href="/api/feeds">Feeds API</a> |
                    <a href="/api/alerts">Alerts API</a> |
                    <a href="/api/rules">Rules API</a> |
                    <a href="/logout">Logout</a>
                </p>
            </body>
            </html>
            """

        @app.route('/api/stats')
        @login_required
        def api_stats():
            return jsonify(self.get_indicator_stats())

        @app.route('/api/indicators', methods=['GET', 'POST'])
        @login_required
        def api_indicators():
            if request.method == 'POST':
                data = request.get_json(silent=True) or {}
                if not data:
                    data = request.form.to_dict()
                    if 'tags' in data and isinstance(data['tags'], str):
                        data['tags'] = [tag.strip() for tag in data['tags'].split(',') if tag.strip()]
                    if 'confidence' in data:
                        try:
                            data['confidence'] = int(data['confidence'])
                        except (TypeError, ValueError):
                            data['confidence'] = 50
                    if 'context' in data and isinstance(data['context'], str):
                        try:
                            data['context'] = json.loads(data['context']) if data['context'].strip() else {}
                        except json.JSONDecodeError:
                            return jsonify({'error': 'context must be valid JSON'}), 400

                if not self.add_indicator(data):
                    return jsonify({'error': 'type and value are required'}), 400
                return jsonify({'status': 'created'}), 201

            query = {
                'type': request.args.get('type'),
                'value': request.args.get('value'),
                'severity': request.args.get('severity'),
                'confidence': request.args.get('confidence'),
                'source': request.args.get('source'),
                'tags': [tag for tag in request.args.get('tags', '').split(',') if tag]
            }
            return jsonify(self.search_indicators(query))

        @app.route('/api/indicators/<indicator_id>')
        @login_required
        def api_indicator(indicator_id):
            indicator = self.indicators.get(indicator_id)
            if not indicator:
                return jsonify({'error': 'Indicator not found'}), 404
            return jsonify(indicator)

        @app.route('/api/feeds', methods=['GET'])
        @login_required
        def api_feeds():
            return jsonify(list(self.feeds.values()))

        @app.route('/api/feeds/<feed_id>/enable', methods=['POST'])
        @login_required
        def api_enable_feed(feed_id):
            feed = self.feeds.get(feed_id)
            if not feed:
                return jsonify({'error': 'Feed not found'}), 404

            feed['enabled'] = True
            self.cursor.execute("UPDATE feeds SET enabled = 1 WHERE id = ?", (feed_id,))
            self.conn.commit()
            return jsonify({'status': 'enabled', 'feed': feed})

        @app.route('/api/feeds/<feed_id>/disable', methods=['POST'])
        @login_required
        def api_disable_feed(feed_id):
            feed = self.feeds.get(feed_id)
            if not feed:
                return jsonify({'error': 'Feed not found'}), 404

            feed['enabled'] = False
            self.cursor.execute("UPDATE feeds SET enabled = 0 WHERE id = ?", (feed_id,))
            self.conn.commit()
            return jsonify({'status': 'disabled', 'feed': feed})

        @app.route('/api/feeds/<feed_id>/refresh', methods=['POST'])
        @login_required
        def api_refresh_feed(feed_id):
            feed = self.feeds.get(feed_id)
            if not feed:
                return jsonify({'error': 'Feed not found'}), 404

            try:
                if feed['type'] == 'otx':
                    self.update_otx_feed(feed)
                elif feed['type'] == 'misp':
                    self.update_misp_feed(feed)
                elif feed['type'] == 'phishtank':
                    self.update_phishtank_feed(feed)
                elif feed['type'] == 'urlhaus':
                    self.update_urlhaus_feed(feed)
                else:
                    return jsonify({'error': 'Unsupported feed type'}), 400

                feed['last_update'] = datetime.now().isoformat()
                self.cursor.execute(
                    "UPDATE feeds SET last_update = ? WHERE id = ?",
                    (feed['last_update'], feed_id)
                )
                self.conn.commit()
                return jsonify({'status': 'updated', 'feed': feed})
            except Exception as exc:
                logging.error(f"Manual feed refresh failed for {feed_id}: {exc}")
                return jsonify({'error': str(exc)}), 500

        @app.route('/api/alerts')
        @login_required
        def api_alerts():
            self.cursor.execute(
                "SELECT id, title, description, severity, status, created, updated, assigned_to, indicators, source FROM alerts ORDER BY created DESC"
            )
            rows = self.cursor.fetchall()
            alerts = serialize_rows(
                rows,
                ['id', 'title', 'description', 'severity', 'status', 'created', 'updated', 'assigned_to', 'indicators', 'source']
            )
            for alert in alerts:
                alert['indicators'] = json.loads(alert['indicators']) if alert['indicators'] else []
            return jsonify(alerts)

        @app.route('/api/alerts', methods=['POST'])
        @login_required
        def api_create_alert():
            data = request.get_json(silent=True) or request.form.to_dict()
            current_time = datetime.now().isoformat()
            alert_id = str(uuid.uuid4())
            indicators = data.get('indicators', [])

            if isinstance(indicators, str):
                try:
                    indicators = json.loads(indicators)
                except json.JSONDecodeError:
                    indicators = [item.strip() for item in indicators.split(',') if item.strip()]

            title = data.get('title')
            if not title:
                return jsonify({'error': 'title is required'}), 400

            alert = {
                'id': alert_id,
                'title': title,
                'description': data.get('description', ''),
                'severity': data.get('severity', 'medium'),
                'status': data.get('status', 'new'),
                'created': current_time,
                'updated': current_time,
                'assigned_to': data.get('assigned_to'),
                'indicators': indicators,
                'source': data.get('source', 'manual')
            }

            self.cursor.execute(
                '''
                INSERT INTO alerts
                (id, title, description, severity, status, created, updated, assigned_to, indicators, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    alert['id'],
                    alert['title'],
                    alert['description'],
                    alert['severity'],
                    alert['status'],
                    alert['created'],
                    alert['updated'],
                    alert['assigned_to'],
                    json.dumps(alert['indicators']),
                    alert['source']
                )
            )
            self.conn.commit()
            return jsonify({'status': 'created', 'alert': alert}), 201

        @app.route('/api/rules', methods=['GET', 'POST'])
        @login_required
        def api_rules():
            if request.method == 'POST':
                data = request.get_json(silent=True) or request.form.to_dict()
                if not data.get('name') or not data.get('condition') or not data.get('action'):
                    return jsonify({'error': 'name, condition, and action are required'}), 400

                current_time = datetime.now().isoformat()
                rule = {
                    'id': str(uuid.uuid4()),
                    'name': data['name'],
                    'description': data.get('description', ''),
                    'condition': data['condition'],
                    'action': data['action'],
                    'enabled': 1 if str(data.get('enabled', '1')).lower() not in ('0', 'false', 'no') else 0,
                    'created': current_time,
                    'updated': current_time
                }

                self.cursor.execute(
                    '''
                    INSERT INTO rules
                    (id, name, description, condition, action, enabled, created, updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        rule['id'],
                        rule['name'],
                        rule['description'],
                        rule['condition'],
                        rule['action'],
                        rule['enabled'],
                        rule['created'],
                        rule['updated']
                    )
                )
                self.conn.commit()
                return jsonify({'status': 'created', 'rule': rule}), 201

            self.cursor.execute(
                "SELECT id, name, description, condition, action, enabled, created, updated FROM rules ORDER BY name"
            )
            rows = self.cursor.fetchall()
            rules = serialize_rows(
                rows,
                ['id', 'name', 'description', 'condition', 'action', 'enabled', 'created', 'updated']
            )
            return jsonify(rules)

        @app.route('/ui/indicators', methods=['POST'])
        @login_required
        def ui_add_indicator():
            form_data = request.form.to_dict()
            form_data['tags'] = [tag.strip() for tag in form_data.get('tags', '').split(',') if tag.strip()]
            try:
                form_data['confidence'] = int(form_data.get('confidence', 50))
            except (TypeError, ValueError):
                form_data['confidence'] = 50
            try:
                form_data['context'] = json.loads(form_data.get('context', '{}') or '{}')
            except json.JSONDecodeError:
                return "Context must be valid JSON", 400

            if not self.add_indicator(form_data):
                return "Indicator type and value are required", 400
            return redirect(url_for('dashboard'))

        @app.route('/ui/rules', methods=['POST'])
        @login_required
        def ui_add_rule():
            form_data = request.form.to_dict()
            if not form_data.get('name') or not form_data.get('condition') or not form_data.get('action'):
                return "Name, condition, and action are required", 400

            current_time = datetime.now().isoformat()
            self.cursor.execute(
                '''
                INSERT INTO rules
                (id, name, description, condition, action, enabled, created, updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    str(uuid.uuid4()),
                    form_data['name'],
                    form_data.get('description', ''),
                    form_data['condition'],
                    form_data['action'],
                    1 if form_data.get('enabled', '1') == '1' else 0,
                    current_time,
                    current_time
                )
            )
            self.conn.commit()
            return redirect(url_for('dashboard'))

        host = self.config.get('host', '127.0.0.1')
        port = self.config.get('port', 5000)
        debug = self.config.get('debug', False)

        logging.info(f"Starting TIP web server on {host}:{port}")
        app.run(host=host, port=port, debug=debug, use_reloader=False)


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description="Threat Intelligence Platform")
    parser.add_argument('--host', default='127.0.0.1', help='Host interface for the web server')
    parser.add_argument('--port', type=int, default=5000, help='Port for the web server')
    parser.add_argument('--db-path', default='tip.db', help='Path to SQLite database file')
    parser.add_argument('--secret-key', default=None, help='Flask session secret key')
    parser.add_argument('--initial-admin-password', default=None, help='Initial password for the first admin user')
    parser.add_argument('--debug', action='store_true', help='Enable Flask debug mode')
    parser.add_argument(
        '--no-feed-updates',
        action='store_true',
        help='Disable background feed update threads at startup'
    )
    return parser.parse_args()


def main():
    """Application entrypoint"""
    args = parse_args()
    config = {
        'host': args.host,
        'port': args.port,
        'db_path': args.db_path,
        'secret_key': args.secret_key,
        'initial_admin_password': args.initial_admin_password,
        'debug': args.debug,
        'enable_feed_updates': not args.no_feed_updates
    }

    platform = ThreatIntelPlatform(config)
    platform.start_web_server()


if __name__ == '__main__':
    main()


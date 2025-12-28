"""
Test suite for Python Network Dashboard server
Run with: pytest test_server.py -v
"""

import pytest
import os
import sys

# Set environment variables BEFORE importing server
os.environ['DASHBOARD_TOKEN'] = 'test-token-12345'
os.environ['ALLOW_TERMINATE'] = 'true'

# Import after setting env vars
import importlib
if 'server' in sys.modules:
    # Reload if already imported
    import server
    importlib.reload(server)
    app = server.app
    CRITICAL_PROCESSES = server.CRITICAL_PROCESSES
else:
    from server import app, CRITICAL_PROCESSES


@pytest.fixture
def client():
    """Create test client with authentication enabled"""
    app.config['TESTING'] = True

    with app.test_client() as client:
        yield client


@pytest.fixture
def authenticated_client(client):
    """Create authenticated test client with cookie"""
    # Login to get cookie
    response = client.post('/api/login',
                          json={'token': 'test-token-12345'},
                          content_type='application/json')
    assert response.status_code == 200
    return client


def test_config_endpoint(client):
    """Config endpoint should work without authentication"""
    response = client.get('/api/config')
    assert response.status_code == 200
    data = response.get_json()
    assert 'auth_required' in data
    assert 'terminate_enabled' in data


def test_login_with_valid_token(client):
    """Valid token should authenticate and set cookie"""
    response = client.post('/api/login',
                          json={'token': 'test-token-12345'},
                          content_type='application/json')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'authenticated'

    # Check that cookie was set in response headers
    assert 'Set-Cookie' in response.headers
    assert 'auth_token' in response.headers.get('Set-Cookie', '')


def test_login_with_invalid_token(client):
    """Invalid token should fail authentication"""
    response = client.post('/api/login',
                          json={'token': 'wrong-token'},
                          content_type='application/json')
    assert response.status_code == 401
    data = response.get_json()
    assert 'error' in data


def test_connections_requires_auth(client):
    """Unauthenticated request should fail"""
    response = client.get('/api/connections')
    assert response.status_code == 401


def test_connections_with_auth(authenticated_client):
    """Authenticated request should succeed"""
    response = authenticated_client.get('/api/connections')
    assert response.status_code == 200
    data = response.get_json()
    assert 'connections' in data
    assert 'total' in data
    assert 'limit' in data
    assert 'offset' in data


def test_input_validation_limit(authenticated_client):
    """Limit should be capped at 500"""
    response = authenticated_client.get('/api/connections?limit=9999')
    assert response.status_code == 200
    data = response.get_json()
    assert data['limit'] <= 500


def test_input_validation_invalid_limit(authenticated_client):
    """Invalid limit should return 400 error"""
    response = authenticated_client.get('/api/connections?limit=invalid')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_input_validation_invalid_state_filter(authenticated_client):
    """Invalid state filter should return 400 error"""
    response = authenticated_client.get('/api/connections?state=INVALID_STATE')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_input_validation_valid_state_filter(authenticated_client):
    """Valid state filter should succeed"""
    response = authenticated_client.get('/api/connections?state=ESTABLISHED')
    assert response.status_code == 200


def test_protected_process_list_exists():
    """Critical processes list should contain system processes"""
    assert len(CRITICAL_PROCESSES) > 0
    # Check for common critical processes
    critical_lower = [p.lower() for p in CRITICAL_PROCESSES]
    assert any('system' in p for p in critical_lower) or any('init' in p for p in critical_lower)


def test_system_endpoint(authenticated_client):
    """System endpoint should return hostname and IP"""
    response = authenticated_client.get('/api/system')
    assert response.status_code == 200
    data = response.get_json()
    assert 'hostname' in data
    assert 'ip' in data


def test_stats_endpoint(authenticated_client):
    """Stats endpoint should return connection statistics"""
    response = authenticated_client.get('/api/stats')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Stats' in data
    assert 'TopProcesses' in data
    assert 'Timestamp' in data


def test_logout(authenticated_client):
    """Logout should clear the cookie"""
    response = authenticated_client.post('/api/logout')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'logged out'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

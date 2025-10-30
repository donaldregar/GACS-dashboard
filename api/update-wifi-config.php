<?php
require_once __DIR__ . '/../config/config.php';
requireLogin();

use App\GenieACS;

header('Content-Type: application/json');

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Get POST data
$input = json_decode(file_get_contents('php://input'), true);

// Validate input
if (!isset($input['device_id']) || empty($input['device_id'])) {
    jsonResponse(['success' => false, 'message' => 'Device ID is required']);
    exit;
}

if (!isset($input['wifi_ssid']) || empty($input['wifi_ssid'])) {
    jsonResponse(['success' => false, 'message' => 'WiFi SSID is required']);
    exit;
}

$deviceId = clean($input['device_id']);
$wifiSsid = clean($input['wifi_ssid']);
$securityMode = isset($input['security_mode']) ? clean($input['security_mode']) : 'WPA2PSK';
$wifiPassword = isset($input['wifi_password']) ? clean($input['wifi_password']) : '';
$wlanIndex = isset($input['wlan_index']) ? intval($input['wlan_index']) : 1;

/**
 * Attempt to find the requested device inside the local database to satisfy
 * operators that need to verify where the data originates from and whether the
 * device/client mapping exists. We look inside `map_items` (primary storage for
 * topology items) and join with `onu_config` to expose customer assignments.
 *
 * @param mysqli $db
 * @param string $deviceId
 * @return array|null
 */
function findDeviceMetadata($db, $deviceId)
{
    $metadata = null;

    $stmt = $db->prepare(
        "SELECT mi.id AS map_item_id, mi.name, mi.item_type, mi.status, mi.latitude, mi.longitude, " .
        "       onu.customer_name, onu.odp_port, onu.id AS onu_config_id " .
        "FROM map_items mi " .
        "LEFT JOIN onu_config onu ON onu.map_item_id = mi.id " .
        "WHERE mi.genieacs_device_id = ? " .
        "LIMIT 1"
    );

    if ($stmt) {
        $stmt->bind_param('s', $deviceId);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result && $result->num_rows > 0) {
            $metadata = $result->fetch_assoc();
        }
        $stmt->close();
    }

    // Fallback: there may be legacy records stored only in onu_config.
    if ($metadata === null) {
        $legacyStmt = $db->prepare(
            "SELECT id AS onu_config_id, map_item_id, customer_name, odp_port " .
            "FROM onu_config WHERE genieacs_device_id = ? LIMIT 1"
        );

        if ($legacyStmt) {
            $legacyStmt->bind_param('s', $deviceId);
            $legacyStmt->execute();
            $legacyResult = $legacyStmt->get_result();
            if ($legacyResult && $legacyResult->num_rows > 0) {
                $metadata = $legacyResult->fetch_assoc();
            }
            $legacyStmt->close();
        }
    }

    return $metadata;
}

// Validate SSID length (1-32 characters)
if (strlen($wifiSsid) < 1 || strlen($wifiSsid) > 32) {
    jsonResponse(['success' => false, 'message' => 'WiFi SSID must be between 1 and 32 characters']);
    exit;
}

// Validate password length only if security mode is not Open
if ($securityMode !== 'None') {
    if (empty($wifiPassword)) {
        jsonResponse(['success' => false, 'message' => 'WiFi Password is required for secured network']);
        exit;
    }

    if (strlen($wifiPassword) < 8 || strlen($wifiPassword) > 63) {
        jsonResponse(['success' => false, 'message' => 'WiFi Password must be between 8 and 63 characters']);
        exit;
    }
}

try {
    // Get GenieACS credentials from database
    $db = getDBConnection();
    $deviceMetadata = findDeviceMetadata($db, $deviceId);

    $buildResponseData = function (array $data = []) use ($deviceId, $deviceMetadata) {
        return array_merge([
            'device_id' => $deviceId,
            'database' => DB_NAME,
            'matched_device' => $deviceMetadata
        ], $data);
    };

    $stmt = $db->prepare("SELECT host, port, username, password FROM genieacs_credentials LIMIT 1");
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        jsonResponse(['success' => false, 'message' => 'GenieACS not configured. Please configure it first.']);
        exit;
    }

    $config = $result->fetch_assoc();
    $stmt->close();

    // Initialize GenieACS client
    $genieacs = new GenieACS(
        $config['host'],
        $config['port'],
        $config['username'],
        $config['password']
    );

    // Get device info to check ConnectionRequestURL
    $deviceResult = $genieacs->getDevice($deviceId);
    $canConnectionRequest = true;
    $deviceSnapshot = null;

    if ($deviceResult['success']) {
        $device = $deviceResult['data'];
        $deviceSnapshot = $device;
        $connectionUrl = null;

        // Try to get ConnectionRequestURL
        if (isset($device['InternetGatewayDevice']['ManagementServer']['ConnectionRequestURL']['_value'])) {
            $connectionUrl = $device['InternetGatewayDevice']['ManagementServer']['ConnectionRequestURL']['_value'];
        } elseif (isset($device['Device']['ManagementServer']['ConnectionRequestURL']['_value'])) {
            $connectionUrl = $device['Device']['ManagementServer']['ConnectionRequestURL']['_value'];
        }

        // Check if URL contains private IP (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
        if ($connectionUrl) {
            if (preg_match('/https?:\/\/(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/', $connectionUrl)) {
                $canConnectionRequest = false;
            }
        }
    }

    // Set WiFi configuration
    $result = $genieacs->setWiFiConfig($deviceId, $wifiSsid, $wifiPassword, $wlanIndex, $securityMode, $deviceSnapshot);

    if ($result['success']) {
        // Check HTTP code
        $httpCode = $result['http_code'] ?? 0;

        if ($httpCode === 200) {
            jsonResponse([
                'success' => true,
                'message' => 'WiFi configuration updated successfully! Device responded immediately.',
                'data' => $buildResponseData([
                    'wifi_ssid' => $wifiSsid,
                    'security_mode' => $securityMode,
                    'wlan_index' => $wlanIndex,
                    'response_time' => 'immediate'
                ])
            ]);
            exit;
        } elseif ($httpCode === 202) {
            // Task queued - determine estimated wait time
            if (!$canConnectionRequest) {
                jsonResponse([
                    'success' => true,
                    'message' => 'WiFi configuration task queued successfully. Device is behind NAT - changes will apply on next inform cycle (typically 30-60 minutes) or you can manually reboot the device now.',
                    'data' => $buildResponseData([
                        'wifi_ssid' => $wifiSsid,
                        'security_mode' => $securityMode,
                        'wlan_index' => $wlanIndex,
                        'response_time' => 'delayed',
                        'reason' => 'nat',
                        'estimated_wait' => '30-60 minutes or manual reboot'
                    ])
                ]);
                exit;
            } else {
                jsonResponse([
                    'success' => true,
                    'message' => 'WiFi configuration task queued. Device will update when it connects to GenieACS.',
                    'data' => $buildResponseData([
                        'wifi_ssid' => $wifiSsid,
                        'security_mode' => $securityMode,
                        'wlan_index' => $wlanIndex,
                        'response_time' => 'delayed'
                    ])
                ]);
                exit;
            }
        } else {
            jsonResponse([
                'success' => true,
                'message' => 'WiFi configuration task sent to device.',
                'data' => $buildResponseData([
                    'wifi_ssid' => $wifiSsid,
                    'security_mode' => $securityMode,
                    'wlan_index' => $wlanIndex,
                    'http_code' => $httpCode
                ])
            ]);
            exit;
        }
    } else {
        $errorMsg = isset($result['error']) ? $result['error'] : 'Failed to update WiFi configuration';
        jsonResponse([
            'success' => false,
            'message' => $errorMsg,
            'data' => $buildResponseData([
                'http_code' => $result['http_code'] ?? 0
            ])
        ]);
        exit;
    }

} catch (Exception $e) {
    jsonResponse([
        'success' => false,
        'message' => 'Error: ' . $e->getMessage(),
        'data' => [
            'device_id' => $deviceId,
            'database' => DB_NAME
        ]
    ]);
    exit;
}

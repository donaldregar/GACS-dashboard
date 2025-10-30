<?php
namespace App;

/**
 * GenieACS API Client
 */
class GenieACS {
    private $host;
    private $port;
    private $username;
    private $password;
    private $baseUrl;

    public function __construct($host = null, $port = 7557, $username = null, $password = null) {
        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;
        $this->baseUrl = "http://{$this->host}:{$this->port}";
    }

    /**
     * Make HTTP request to GenieACS API
     */
    private function request($endpoint, $method = 'GET', $data = null) {
        $url = $this->baseUrl . $endpoint;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        // Add authentication if provided
        if ($this->username && $this->password) {
            curl_setopt($ch, CURLOPT_USERPWD, "{$this->username}:{$this->password}");
        }

        // Set method and data
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($data) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            }
        } elseif ($method === 'PUT') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            if ($data) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            }
        } elseif ($method === 'DELETE') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return ['success' => false, 'error' => $error];
        }

        return [
            'success' => $httpCode >= 200 && $httpCode < 300,
            'data' => json_decode($response, true),
            'http_code' => $httpCode
        ];
    }

    /**
     * Test connection to GenieACS
     */
    public function testConnection() {
        $result = $this->request('/devices?limit=1');
        return $result['success'];
    }

    /**
     * Get all devices
     */
    public function getDevices($query = []) {
        $queryString = empty($query) ? '' : '?query=' . urlencode(json_encode($query));
        return $this->request('/devices/' . $queryString);
    }

    /**
     * Get device by ID
     */
    public function getDevice($deviceId) {
        $query = ['_id' => $deviceId];
        $result = $this->request('/devices/?query=' . urlencode(json_encode($query)));

        if ($result['success'] && !empty($result['data'])) {
            return ['success' => true, 'data' => $result['data'][0]];
        }

        return ['success' => false, 'error' => 'Device not found'];
    }

    /**
     * Get device parameters
     */
    public function getDeviceParameters($deviceId) {
        return $this->getDevice($deviceId);
    }

    /**
     * Execute task on device
     */
    public function executeTask($deviceId, $taskName, $params = []) {
        $endpoint = "/devices/{$deviceId}/tasks";
        $data = [
            'name' => $taskName
        ];

        if (!empty($params)) {
            $data['parameterValues'] = $params;
        }

        return $this->request($endpoint, 'POST', $data);
    }

    /**
     * Summon device (connection request)
     */
    public function summonDevice($deviceId) {
        // URL encode device ID to handle special characters
        $encodedId = rawurlencode($deviceId);
        $endpoint = "/devices/{$encodedId}/tasks?connection_request";
        return $this->request($endpoint, 'POST');
    }

    /**
     * Reboot device
     */
    public function rebootDevice($deviceId) {
        return $this->executeTask($deviceId, 'reboot');
    }

    /**
     * Set parameter values on device
     *
     * @param string $deviceId Device ID
     * @param array $parameters Array of parameters to set [['path', 'value', 'type'], ...]
     * @param int $timeout Timeout in milliseconds (default: 3000)
     * @return array Response with success status
     *
     * Example:
     * $parameters = [
     *     ['InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', 'NewSSID', 'xsd:string'],
     *     ['InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase', 'NewPassword', 'xsd:string']
     * ];
     */
    public function setParameterValues($deviceId, $parameters, $timeout = 3000) {
        // URL encode device ID to handle special characters
        $encodedId = rawurlencode($deviceId);
        $endpoint = "/devices/{$encodedId}/tasks?timeout={$timeout}&connection_request";

        $data = [
            'name' => 'setParameterValues',
            'parameterValues' => $parameters
        ];

        return $this->request($endpoint, 'POST', $data);
    }

    /**
     * Determine if a parameter path exists on the provided device snapshot.
     */
    private function parameterExists($deviceData, $path) {
        if ($deviceData === null) {
            return false;
        }

        $segments = explode('.', $path);
        $current = $deviceData;

        foreach ($segments as $segment) {
            if (!is_array($current) || !array_key_exists($segment, $current)) {
                return false;
            }
            $current = $current[$segment];
        }

        if (is_array($current)) {
            if (array_key_exists('_value', $current) || array_key_exists('_object', $current)) {
                return true;
            }

            foreach ($current as $key => $value) {
                if (in_array($key, ['_timestamp', '_type'], true)) {
                    continue;
                }

                if ($value !== null) {
                    return true;
                }
            }

            return false;
        }

        return $current !== null;
    }

    /**
     * Filter parameter paths based on device snapshot availability.
     */
    private function filterAvailablePaths(array $paths, $deviceData = null, array $fallback = []) {
        if ($deviceData === null) {
            return array_values(array_unique(array_merge($paths, $fallback)));
        }

        $available = [];

        foreach ($paths as $path) {
            if ($this->parameterExists($deviceData, $path)) {
                $available[] = $path;
            }
        }

        if (empty($available)) {
            foreach ($fallback as $path) {
                if (!in_array($path, $available, true)) {
                    $available[] = $path;
                }
            }
        }

        return $available;
    }

    /**
     * Set WiFi configuration (SSID, Password, and Security Mode)
     *
     * @param string $deviceId Device ID
     * @param string $ssid New WiFi SSID
     * @param string $password New WiFi Password (optional for Open network)
     * @param int $wlanIndex WLAN Configuration index (default: 1)
     * @param string $securityMode Security mode (WPA2PSK, WPAPSK, WPA2PSKWPAPSK, None)
     * @param array|null $deviceData Optional device snapshot for path detection
     * @return array Response with success status
     */
    public function setWiFiConfig($deviceId, $ssid, $password = '', $wlanIndex = 1, $securityMode = 'WPA2PSK', $deviceData = null) {
        $parameters = [];

        $defaultTr098 = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.{$wlanIndex}";
        $defaultTr181 = "Device.WiFi";

        $isTr181 = $deviceData !== null && isset($deviceData['Device']);
        $isTr098 = $deviceData !== null && isset($deviceData['InternetGatewayDevice']);

        $ssidFallback = ["{$defaultTr098}.SSID"];
        if ($deviceData === null || $isTr181) {
            $ssidFallback[] = "{$defaultTr181}.SSID.{$wlanIndex}.SSID";
        }

        $securityFallback = ["{$defaultTr098}.BeaconType"];
        if ($deviceData === null || $isTr181) {
            $securityFallback[] = "Device.WiFi.AccessPoint.{$wlanIndex}.Security.ModeEnabled";
        }

        $passwordFallback = [];
        if ($deviceData === null || $isTr098) {
            $passwordFallback[] = "{$defaultTr098}.KeyPassphrase";
        }
        if ($deviceData === null || $isTr181) {
            $passwordFallback[] = "Device.WiFi.AccessPoint.{$wlanIndex}.Security.KeyPassphrase";
        }

        $ssidPaths = $this->filterAvailablePaths([
            "{$defaultTr098}.SSID",
            "{$defaultTr181}.SSID.{$wlanIndex}.SSID"
        ], $deviceData, $ssidFallback);

        $securityPaths = $this->filterAvailablePaths([
            "{$defaultTr098}.BeaconType",
            "Device.WiFi.AccessPoint.{$wlanIndex}.Security.ModeEnabled"
        ], $deviceData, $securityFallback);

        $passwordPaths = $this->filterAvailablePaths([
            "{$defaultTr098}.KeyPassphrase",
            "{$defaultTr098}.PreSharedKey.1.KeyPassphrase",
            "{$defaultTr098}.PreSharedKey.1.PreSharedKey",
            "Device.WiFi.AccessPoint.{$wlanIndex}.Security.KeyPassphrase",
            "Device.WiFi.AccessPoint.{$wlanIndex}.Security.PreSharedKey"
        ], $deviceData, $passwordFallback);

        $authPaths = $this->filterAvailablePaths([
            "{$defaultTr098}.WPAAuthenticationMode"
        ], $deviceData);

        $encryptionPaths = $this->filterAvailablePaths([
            "{$defaultTr098}.WPAEncryptionModes"
        ], $deviceData);

        foreach ($ssidPaths as $path) {
            $parameters[] = [$path, $ssid, 'xsd:string'];
        }

        $beaconTypeMap = [
            'WPA2PSK' => '11i',
            'WPAPSK' => 'WPA',
            'WPA2PSKWPAPSK' => 'WPAand11i',
            'None' => 'Basic'
        ];

        $modeEnabledMap = [
            'WPA2PSK' => 'WPA2-PSK',
            'WPAPSK' => 'WPA-PSK',
            'WPA2PSKWPAPSK' => 'WPA-WPA2-PSK',
            'None' => 'None'
        ];

        foreach ($securityPaths as $path) {
            if (strpos($path, 'BeaconType') !== false) {
                $value = $beaconTypeMap[$securityMode] ?? '11i';
                $parameters[] = [$path, $value, 'xsd:string'];
            } elseif (strpos($path, 'ModeEnabled') !== false) {
                $value = $modeEnabledMap[$securityMode] ?? 'WPA2-PSK';
                $parameters[] = [$path, $value, 'xsd:string'];
            }
        }

        if ($securityMode !== 'None' && !empty($password)) {
            foreach ($passwordPaths as $path) {
                $parameters[] = [$path, $password, 'xsd:string'];
            }

            foreach ($authPaths as $path) {
                $parameters[] = [$path, 'PSKAuthentication', 'xsd:string'];
            }

            foreach ($encryptionPaths as $path) {
                $encryptionMode = ($securityMode === 'WPA2PSK' || $securityMode === 'WPA2PSKWPAPSK') ? 'AESEncryption' : 'TKIPEncryption';
                $parameters[] = [$path, $encryptionMode, 'xsd:string'];
            }
        } elseif ($securityMode === 'None') {
            // Explicitly clear passwords when switching to open network
            foreach ($passwordPaths as $path) {
                $parameters[] = [$path, '', 'xsd:string'];
            }
        }

        return $this->setParameterValues($deviceId, $parameters);
    }

    /**
     * Get device statistics
     */
    public function getDeviceStats() {
        $devices = $this->getDevices();

        if (!$devices['success']) {
            return ['success' => false, 'error' => 'Failed to fetch devices'];
        }

        $total = count($devices['data']);
        $online = 0;
        $offline = 0;

        foreach ($devices['data'] as $device) {
            // Check last inform time (within last 5 minutes = online)
            $lastInform = isset($device['_lastInform']) ? $device['_lastInform'] : null;

            $isOnline = false;

            if ($lastInform) {
                // Convert ISO 8601 to Unix timestamp
                $lastInformTimestamp = strtotime($lastInform);
                if ($lastInformTimestamp !== false) {
                    // Online if last inform within 5 minutes
                    $isOnline = (time() - $lastInformTimestamp) < 300;
                }
            }

            if ($isOnline) {
                $online++;
            } else {
                $offline++;
            }
        }

        return [
            'success' => true,
            'data' => [
                'total' => $total,
                'online' => $online,
                'offline' => $offline
            ]
        ];
    }

    /**
     * Parse device data for display
     */
    public function parseDeviceData($device) {
        $data = [];

        // Helper function to get nested parameter value
        $getParam = function($path) use ($device) {
            $keys = explode('.', $path);
            $value = $device;

            foreach ($keys as $key) {
                if (isset($value[$key])) {
                    $value = $value[$key];
                } else {
                    return null;
                }
            }

            // GenieACS uses object format with _value field
            if (is_array($value) && isset($value['_value'])) {
                return $value['_value'];
            }

            // Fallback for direct values
            return is_array($value) ? null : $value;
        };

        // Basic info
        $data['device_id'] = $device['_id'] ?? 'N/A';
        $data['serial_number'] = $getParam('_deviceId._SerialNumber') ?? $getParam('InternetGatewayDevice.DeviceInfo.SerialNumber') ?? 'N/A';

        // MAC Address - try multiple paths
        $macAddress = $getParam('InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress') ??
                     $getParam('InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress') ??
                     $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.BSSID') ??
                     $getParam('Device.Ethernet.Interface.1.MACAddress') ??
                     $getParam('_deviceId._MACAddress');

        // If MAC still not found, try to construct from OUI and serial number
        if (empty($macAddress) || $macAddress === 'N/A') {
            $oui = $getParam('_deviceId._OUI');
            $serial = $getParam('_deviceId._SerialNumber');

            // Some devices have MAC embedded in serial number (last 6 chars)
            if ($oui && $serial && strlen($serial) >= 6) {
                $lastSixChars = substr($serial, -6);
                // Check if last 6 chars are hex
                if (ctype_xdigit($lastSixChars)) {
                    // Format OUI properly (F86CE1 -> F8:6C:E1)
                    $ouiFormatted = strtoupper(substr($oui, 0, 2) . ':' .
                                               substr($oui, 2, 2) . ':' .
                                               substr($oui, 4, 2));

                    $macAddress = $ouiFormatted . ':' .
                                 strtoupper(substr($lastSixChars, 0, 2)) . ':' .
                                 strtoupper(substr($lastSixChars, 2, 2)) . ':' .
                                 strtoupper(substr($lastSixChars, 4, 2));
                }
            }
        }

        $data['mac_address'] = $macAddress ?? 'N/A';
        $data['manufacturer'] = $getParam('_deviceId._Manufacturer') ?? $getParam('InternetGatewayDevice.DeviceInfo.Manufacturer') ?? 'N/A';
        $data['oui'] = $getParam('_deviceId._OUI') ?? $getParam('InternetGatewayDevice.DeviceInfo.ManufacturerOUI') ?? 'N/A';
        $data['product_class'] = $getParam('_deviceId._ProductClass') ?? $getParam('InternetGatewayDevice.DeviceInfo.ProductClass') ?? 'N/A';
        $data['hardware_version'] = $getParam('InternetGatewayDevice.DeviceInfo.HardwareVersion') ?? 'N/A';
        $data['software_version'] = $getParam('InternetGatewayDevice.DeviceInfo.SoftwareVersion') ?? 'N/A';

        // Status
        $lastInform = isset($device['_lastInform']) ? $device['_lastInform'] : null;

        if ($lastInform) {
            $lastInformTimestamp = strtotime($lastInform);
            if ($lastInformTimestamp !== false) {
                $data['last_inform'] = date('Y-m-d H:i:s', $lastInformTimestamp);
                $data['status'] = (time() - $lastInformTimestamp) < 300 ? 'online' : 'offline';
            } else {
                $data['last_inform'] = 'N/A';
                $data['status'] = 'offline';
            }
        } else {
            $data['last_inform'] = 'N/A';
            $data['status'] = 'offline';
        }

        // Network info
        $connectionUrl = $getParam('InternetGatewayDevice.ManagementServer.ConnectionRequestURL') ??
                        $getParam('Device.ManagementServer.ConnectionRequestURL') ?? 'N/A';

        $data['ip_tr069'] = $connectionUrl;

        // Extract IP address from ConnectionRequestURL
        $ipAddress = 'N/A';
        if ($connectionUrl && $connectionUrl !== 'N/A') {
            // Extract IP from URL format: http://IP:PORT/path or https://IP:PORT/path
            if (preg_match('/https?:\/\/([^:\/]+)/', $connectionUrl, $matches)) {
                $ipAddress = $matches[1];
            }
        }

        // Also try WAN IP if available
        if ($ipAddress === 'N/A') {
            $ipAddress = $getParam('InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress') ??
                        $getParam('Device.IP.Interface.1.IPv4Address.1.IPAddress') ?? 'N/A';
        }

        $data['ip_address'] = $ipAddress;
        $data['uptime'] = $getParam('InternetGatewayDevice.DeviceInfo.UpTime') ??
                         $getParam('Device.DeviceInfo.UpTime') ?? 'N/A';

        // WiFi info - try multiple paths and WLAN configurations
        $wifiSsid = $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID') ??
                   $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.SSID') ??
                   $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.3.SSID') ??
                   $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.4.SSID') ??
                   $getParam('Device.WiFi.SSID.1.SSID') ??
                   $getParam('Device.WiFi.SSID.2.SSID');

        $data['wifi_ssid'] = $wifiSsid ?? 'N/A';

        $wifiPassword = $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase') ??
                       $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase') ??
                       $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.KeyPassphrase') ??
                       $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.3.KeyPassphrase') ??
                       $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.4.KeyPassphrase') ??
                       $getParam('Device.WiFi.AccessPoint.1.Security.KeyPassphrase') ??
                       $getParam('Device.WiFi.AccessPoint.2.Security.KeyPassphrase');

        $data['wifi_password'] = $wifiPassword ?? 'N/A';

        // Optical info
        $rxPower = $getParam('VirtualParameters.RXPower') ??
                   $getParam('InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.RXPower') ??
                   $getParam('Device.Optical.Interface.1.RxPower');

        // Convert raw value to dBm if needed
        if ($rxPower !== null && is_numeric($rxPower)) {
            $rxPower = floatval($rxPower);
            if ($rxPower > 100) {
                $rxPower = ($rxPower / 100) - 40;
            }
            $data['rx_power'] = number_format($rxPower, 2);
        } else {
            $data['rx_power'] = $rxPower ?? 'N/A';
        }

        // Temperature
        $temperature = $getParam('VirtualParameters.gettemp') ??
                      $getParam('InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.TransceiverTemperature') ??
                      $getParam('VirtualParameters.Temperature') ??
                      $getParam('InternetGatewayDevice.DeviceInfo.Temperature');

        // Convert raw value if needed (> 1000 indicates raw format)
        if ($temperature !== null && is_numeric($temperature)) {
            $temperature = floatval($temperature);
            if ($temperature > 1000) {
                $temperature = $temperature / 256; // Convert from raw to Celsius
            }
            $data['temperature'] = number_format($temperature, 1);
        } else {
            $data['temperature'] = $temperature ?? 'N/A';
        }

        // WAN Details - try multiple connection types and device numbers
        $wanDetails = [];

        // Helper function to check if WAN connection exists
        $checkWANExists = function($path) use ($device) {
            $keys = explode('.', $path);
            $value = $device;

            foreach ($keys as $key) {
                if (isset($value[$key])) {
                    $value = $value[$key];
                } else {
                    return false;
                }
            }

            // Check if this is an actual connection object (has _object or parameters)
            if (is_array($value)) {
                // If it has _object field and it's true, or has connection parameters
                if (isset($value['_object']) || isset($value['ConnectionStatus']) ||
                    isset($value['Enable']) || isset($value['Name'])) {
                    return true;
                }
            }

            return false;
        };

        // Helper function to detect active WLAN/LAN interfaces
        $detectActiveInterfaces = function() use ($getParam) {
            $activeInterfaces = [];

            // Check WLAN configurations (1-4)
            for ($i = 1; $i <= 4; $i++) {
                $wlanBase = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.{$i}";
                $wlanEnable = $getParam("{$wlanBase}.Enable");
                $wlanStatus = $getParam("{$wlanBase}.Status");
                $wlanSSID = $getParam("{$wlanBase}.SSID");
                $wlanVLAN = $getParam("{$wlanBase}.X_CT-COM_VLAN");

                // WLAN is active if enabled and status is "Up" or has SSID
                if (($wlanEnable === true || $wlanStatus === 'Up') && $wlanSSID) {
                    $activeInterfaces[] = [
                        'type' => 'WLAN',
                        'number' => $i,
                        'interface' => "InternetGatewayDevice.LANDevice.1.WLANConfiguration.{$i}",
                        'ssid' => $wlanSSID,
                        'vlan' => $wlanVLAN ?? 'N/A'
                    ];
                }
            }

            // Check LAN Ethernet configurations (1-4)
            for ($i = 1; $i <= 4; $i++) {
                $lanBase = "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.{$i}";
                $lanEnable = $getParam("{$lanBase}.Enable");
                $lanStatus = $getParam("{$lanBase}.Status");
                $lanVLAN = $getParam("{$lanBase}.X_CT-COM_VLAN");

                // LAN is active if enabled or has status other than "NoLink"
                if ($lanEnable === true || ($lanStatus && $lanStatus !== 'NoLink')) {
                    $activeInterfaces[] = [
                        'type' => 'LAN Ethernet',
                        'number' => $i,
                        'interface' => "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.{$i}",
                        'vlan' => $lanVLAN ?? 'N/A'
                    ];
                }
            }

            return $activeInterfaces;
        };

        // Try WANPPPConnection (most common for PPPoE)
        for ($i = 1; $i <= 8; $i++) {
            $basePath = "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{$i}.WANPPPConnection.1";

            // Check if this connection exists
            if (!$checkWANExists($basePath)) {
                continue;
            }

            $name = $getParam("{$basePath}.Name");
            $externalIP = $getParam("{$basePath}.ExternalIPAddress");
            $serviceList = $getParam("{$basePath}.X_CT-COM_ServiceList");
            $connectionStatus = $getParam("{$basePath}.ConnectionStatus");
            $lanInterface = $getParam("{$basePath}.X_CT-COM_LanInterface");

            // If ConnectionStatus is not available, try to determine from Enable flag
            if (!$connectionStatus || $connectionStatus === 'Unknown') {
                $enabled = $getParam("{$basePath}.Enable");
                if ($enabled !== null) {
                    $connectionStatus = $enabled ? 'Connected' : 'Disconnected';
                } else {
                    $connectionStatus = 'Unknown';
                }
            }

            // Parse LAN interface binding
            $bindingInfo = 'N/A';
            if ($lanInterface !== null && $lanInterface !== '') {
                // Extract interface type and number
                // e.g., "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1" -> "WLAN 1"
                // e.g., "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1" -> "LAN Ethernet 1"
                if (preg_match('/WLANConfiguration\.(\d+)/', $lanInterface, $matches)) {
                    $bindingInfo = "WLAN " . $matches[1];
                } elseif (preg_match('/LANEthernetInterfaceConfig\.(\d+)/', $lanInterface, $matches)) {
                    $bindingInfo = "LAN Ethernet " . $matches[1];
                } elseif (preg_match('/LANHostConfigManagement/', $lanInterface)) {
                    $bindingInfo = "All LAN Ports";
                } else {
                    $bindingInfo = $lanInterface;
                }
            }

            // If binding info is still N/A, try to infer from active interfaces
            if ($bindingInfo === 'N/A') {
                $activeInterfaces = $detectActiveInterfaces();

                if (!empty($activeInterfaces)) {
                    $bindingList = [];
                    foreach ($activeInterfaces as $iface) {
                        if ($iface['type'] === 'WLAN') {
                            $bindingList[] = "WLAN {$iface['number']}";
                        }
                    }

                    if (!empty($bindingList)) {
                        $bindingInfo = implode(', ', $bindingList);
                    }
                }
            }

            // Only add if we have at least a name, IP, or service identifier
            if ($name || $externalIP || $serviceList) {
                // Generate name if not available
                if (!$name) {
                    $name = $serviceList ? "WAN_{$serviceList}_{$i}" : "WAN_PPP_Connection_{$i}";
                }

                $wanDetails[] = [
                    'type' => 'PPPoE',
                    'name' => $name,
                    'status' => $connectionStatus,
                    'connection_type' => $getParam("{$basePath}.ConnectionType") ?? 'N/A',
                    'external_ip' => $externalIP ?? 'N/A',
                    'gateway' => $getParam("{$basePath}.RemoteIPAddress") ?? $getParam("{$basePath}.DefaultGateway") ?? 'N/A',
                    'subnet_mask' => $getParam("{$basePath}.SubnetMask") ?? 'N/A',
                    'dns_servers' => $getParam("{$basePath}.DNSServers") ?? 'N/A',
                    'mac_address' => $getParam("{$basePath}.MACAddress") ?? 'N/A',
                    'username' => $getParam("{$basePath}.Username") ?? 'N/A',
                    'uptime' => $getParam("{$basePath}.Uptime") ?? 'N/A',
                    'last_error' => $getParam("{$basePath}.LastConnectionError") ?? 'N/A',
                    'mru_size' => $getParam("{$basePath}.MaxMRUSize") ?? 'N/A',
                    'binding' => $bindingInfo,
                ];
            }
        }

        // Try WANIPConnection (for DHCP/Static IP)
        for ($i = 1; $i <= 8; $i++) {
            $basePath = "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{$i}.WANIPConnection.1";

            // Check if this connection exists
            if (!$checkWANExists($basePath)) {
                continue;
            }

            $name = $getParam("{$basePath}.Name");
            $externalIP = $getParam("{$basePath}.ExternalIPAddress");
            $serviceList = $getParam("{$basePath}.X_CT-COM_ServiceList");
            $connectionStatus = $getParam("{$basePath}.ConnectionStatus");
            $lanInterface = $getParam("{$basePath}.X_CT-COM_LanInterface");

            // If ConnectionStatus is not available, try to determine from Enable flag
            if (!$connectionStatus || $connectionStatus === 'Unknown') {
                $enabled = $getParam("{$basePath}.Enable");
                if ($enabled !== null) {
                    $connectionStatus = $enabled ? 'Connected' : 'Disconnected';
                } else {
                    $connectionStatus = 'Unknown';
                }
            }

            // Parse LAN interface binding
            $bindingInfo = 'N/A';
            if ($lanInterface !== null && $lanInterface !== '') {
                if (preg_match('/WLANConfiguration\.(\d+)/', $lanInterface, $matches)) {
                    $bindingInfo = "WLAN " . $matches[1];
                } elseif (preg_match('/LANEthernetInterfaceConfig\.(\d+)/', $lanInterface, $matches)) {
                    $bindingInfo = "LAN Ethernet " . $matches[1];
                } elseif (preg_match('/LANHostConfigManagement/', $lanInterface)) {
                    $bindingInfo = "All LAN Ports";
                } else {
                    $bindingInfo = $lanInterface;
                }
            }

            // If binding info is still N/A, try to infer from active interfaces
            if ($bindingInfo === 'N/A') {
                $activeInterfaces = $detectActiveInterfaces();

                if (!empty($activeInterfaces)) {
                    $bindingList = [];
                    foreach ($activeInterfaces as $iface) {
                        if ($iface['type'] === 'WLAN') {
                            $bindingList[] = "WLAN {$iface['number']}";
                        }
                    }

                    if (!empty($bindingList)) {
                        $bindingInfo = implode(', ', $bindingList);
                    }
                }
            }

            // Only add if we have at least a name, IP, or service identifier
            if ($name || $externalIP || $serviceList) {
                // Generate name if not available
                if (!$name) {
                    $name = $serviceList ? "WAN_{$serviceList}_{$i}" : "WAN_IP_Connection_{$i}";
                }

                $wanDetails[] = [
                    'type' => 'IP',
                    'name' => $name,
                    'status' => $connectionStatus,
                    'connection_type' => $getParam("{$basePath}.ConnectionType") ?? 'N/A',
                    'external_ip' => $externalIP ?? 'N/A',
                    'gateway' => $getParam("{$basePath}.DefaultGateway") ?? 'N/A',
                    'subnet_mask' => $getParam("{$basePath}.SubnetMask") ?? 'N/A',
                    'dns_servers' => $getParam("{$basePath}.DNSServers") ?? 'N/A',
                    'mac_address' => $getParam("{$basePath}.MACAddress") ?? 'N/A',
                    'addressing_type' => $getParam("{$basePath}.AddressingType") ?? 'N/A',
                    'uptime' => $getParam("{$basePath}.Uptime") ?? 'N/A',
                    'binding' => $bindingInfo,
                    'username' => 'N/A', // IP connections don't have username
                    'last_error' => 'N/A', // IP connections don't have last error
                    'mru_size' => 'N/A', // IP connections don't have MRU size
                ];
            }
        }

        // If no WAN connections found, try to create virtual WAN details from active interfaces
        if (empty($wanDetails)) {
            $activeInterfaces = $detectActiveInterfaces();

            if (!empty($activeInterfaces)) {
                // Group interfaces by VLAN to create logical WAN connections
                $vlanGroups = [];

                foreach ($activeInterfaces as $iface) {
                    $vlan = $iface['vlan'] !== 'N/A' && $iface['vlan'] !== '' ? $iface['vlan'] : 'default';

                    if (!isset($vlanGroups[$vlan])) {
                        $vlanGroups[$vlan] = [];
                    }
                    $vlanGroups[$vlan][] = $iface;
                }

                // Create WAN detail for each VLAN group
                $connIndex = 1;
                foreach ($vlanGroups as $vlan => $interfaces) {
                    $bindingList = [];

                    foreach ($interfaces as $iface) {
                        if ($iface['type'] === 'WLAN') {
                            $bindingList[] = "WLAN {$iface['number']} ({$iface['ssid']})";
                        } else {
                            $bindingList[] = "{$iface['type']} {$iface['number']}";
                        }
                    }

                    $bindingInfo = implode(', ', $bindingList);

                    // Use device IP as external IP if available
                    $externalIP = $data['ip_address'] ?? 'N/A';

                    $wanDetails[] = [
                        'type' => 'Bridge',
                        'name' => $vlan !== 'default' ? "Bridge_VLAN_{$vlan}" : "Bridge_Connection",
                        'status' => 'Connected',
                        'connection_type' => 'Bridged',
                        'external_ip' => $externalIP,
                        'gateway' => 'N/A',
                        'subnet_mask' => 'N/A',
                        'dns_servers' => 'N/A',
                        'mac_address' => $data['mac_address'] ?? 'N/A',
                        'addressing_type' => 'Bridged',
                        'uptime' => $data['uptime'] ?? 'N/A',
                        'binding' => $bindingInfo,
                        'username' => 'N/A',
                        'last_error' => 'N/A',
                        'mru_size' => 'N/A',
                    ];

                    $connIndex++;
                }
            }
        }

        $data['wan_details'] = $wanDetails;

        return $data;
    }
}

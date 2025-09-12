#!/usr/bin/env python3
"""
Configuration Loader for Advanced Port Scanner
Handles YAML/JSON configuration files with profile support
"""

import os
import json
import logging
import platform
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

logger = logging.getLogger(__name__)

@dataclass
class ScanProfile:
    """Represents a scanning profile with its settings"""
    name: str
    description: str = ""
    host: Optional[str] = None
    ports: Union[str, List[int]] = field(default_factory=list)
    timeout: Optional[float] = None
    workers: Optional[int] = None
    host_concurrency: Optional[int] = None
    enable_banner: Optional[bool] = None
    show_closed: Optional[bool] = None
    ping_sweep: Optional[bool] = None
    output_format: Optional[str] = None
    log_level: Optional[str] = None
    enable_udp: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary, excluding None values"""
        result = {}
        for key, value in self.__dict__.items():
            if value is not None and key != 'name':
                result[key] = value
        return result

class ConfigurationLoader:
    """Handles loading and parsing of configuration files"""
    
    # Hard-coded defaults
    DEFAULT_CONFIG = {
        'timeout': 1.0,
        'workers': 100,
        'host_concurrency': 16,
        'enable_banner': False,
        'show_closed': False,
        'ping_sweep': True,
        'output_format': 'json',
        'log_level': 'INFO',
        'enable_udp': False
    }
    
    # Valid values for validation
    VALID_OUTPUT_FORMATS = {'json', 'csv', 'html', 'none'}
    VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR'}
    
    def __init__(self):
        self.config_paths = self._get_config_paths()
        self.loaded_config: Dict[str, Any] = {}
        self.profiles: Dict[str, ScanProfile] = {}
        
    def _get_config_paths(self) -> List[Path]:
        """Get list of configuration file paths in order of precedence"""
        paths = []
        
        # Current working directory
        cwd_yaml = Path.cwd() / "config.yaml"
        cwd_json = Path.cwd() / "config.json"
        paths.extend([cwd_yaml, cwd_json])
        
        # Platform-specific user config directory
        system = platform.system().lower()
        if system == 'windows':
            config_dir = Path(os.environ.get('APPDATA', '')) / 'AdvancedPortScanner'
        else:
            # Linux/WSL/macOS
            config_dir = Path.home() / '.config' / 'AdvancedPortScanner'
        
        if config_dir:
            config_yaml = config_dir / "config.yaml"
            config_json = config_dir / "config.json"
            paths.extend([config_yaml, config_json])
        
        return paths
    
    def find_config_file(self, custom_path: Optional[str] = None) -> Optional[Path]:
        """Find the first existing configuration file"""
        if custom_path:
            custom_file = Path(custom_path)
            if custom_file.exists():
                return custom_file
            else:
                logger.warning(f"Custom config file not found: {custom_path}")
                return None
        
        for path in self.config_paths:
            if path.exists():
                logger.info(f"Found configuration file: {path}")
                return path
        
        logger.info("No configuration file found, using defaults")
        return None
    
    def _parse_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse YAML or JSON configuration file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
            if not content:
                logger.warning(f"Configuration file is empty: {file_path}")
                return {}
            
            # Try to determine file type by extension first
            if file_path.suffix.lower() == '.yaml' or file_path.suffix.lower() == '.yml':
                if not YAML_AVAILABLE:
                    logger.error("PyYAML is required for YAML configuration files. Install with: pip install PyYAML")
                    return {}
                return yaml.safe_load(content) or {}
            elif file_path.suffix.lower() == '.json':
                return json.loads(content)
            else:
                # Try to auto-detect format
                try:
                    # Try JSON first
                    return json.loads(content)
                except json.JSONDecodeError:
                    if YAML_AVAILABLE:
                        try:
                            return yaml.safe_load(content) or {}
                        except yaml.YAMLError as e:
                            logger.error(f"Failed to parse as YAML: {e}")
                    else:
                        logger.error("Could not parse file as JSON and PyYAML is not available")
                    return {}
                    
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {file_path}")
            return {}
        except Exception as e:
            logger.error(f"Failed to read configuration file {file_path}: {e}")
            return {}
    
    def _validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize configuration values"""
        validated = {}
        
        # Validate defaults section
        defaults = config.get('defaults', {})
        if not isinstance(defaults, dict):
            logger.warning("'defaults' section must be a dictionary, ignoring")
            defaults = {}
        
        for key, value in defaults.items():
            if key == 'timeout':
                try:
                    validated[key] = max(0.1, float(value))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid timeout value: {value}, using default")
                    validated[key] = self.DEFAULT_CONFIG[key]
            elif key == 'workers':
                try:
                    validated[key] = max(1, min(1000, int(value)))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid workers value: {value}, using default")
                    validated[key] = self.DEFAULT_CONFIG[key]
            elif key == 'host_concurrency':
                try:
                    validated[key] = max(1, min(100, int(value)))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid host_concurrency value: {value}, using default")
                    validated[key] = self.DEFAULT_CONFIG[key]
            elif key in ['enable_banner', 'show_closed', 'ping_sweep', 'enable_udp']:
                validated[key] = bool(value)
            elif key == 'output_format':
                if value in self.VALID_OUTPUT_FORMATS:
                    validated[key] = value
                else:
                    logger.warning(f"Invalid output_format: {value}, using default")
                    validated[key] = self.DEFAULT_CONFIG[key]
            elif key == 'log_level':
                if value.upper() in self.VALID_LOG_LEVELS:
                    validated[key] = value.upper()
                else:
                    logger.warning(f"Invalid log_level: {value}, using default")
                    validated[key] = self.DEFAULT_CONFIG[key]
            else:
                # Unknown key, but keep it for extensibility
                validated[key] = value
        
        return validated
    
    def _parse_ports(self, ports_value: Union[str, List[int], int]) -> List[int]:
        """Parse port specification into list of integers"""
        if isinstance(ports_value, int):
            return [ports_value]
        elif isinstance(ports_value, list):
            result = []
            for port in ports_value:
                try:
                    result.append(int(port))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid port in list: {port}")
            return result
        elif isinstance(ports_value, str):
            result = []
            for part in ports_value.split(','):
                part = part.strip()
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-', 1))
                        if start <= end and 1 <= start <= 65535 and 1 <= end <= 65535:
                            result.extend(range(start, end + 1))
                        else:
                            logger.warning(f"Invalid port range: {part}")
                    except ValueError:
                        logger.warning(f"Invalid port range format: {part}")
                else:
                    try:
                        port = int(part)
                        if 1 <= port <= 65535:
                            result.append(port)
                        else:
                            logger.warning(f"Port out of range: {port}")
                    except ValueError:
                        logger.warning(f"Invalid port: {part}")
            return result
        else:
            logger.warning(f"Invalid ports specification: {ports_value}")
            return []
    
    def _load_profiles(self, config: Dict[str, Any]) -> Dict[str, ScanProfile]:
        """Load and validate scanning profiles"""
        profiles = {}
        profiles_section = config.get('profiles', {})
        
        if not isinstance(profiles_section, dict):
            logger.warning("'profiles' section must be a dictionary, ignoring")
            return {}
        
        for profile_name, profile_data in profiles_section.items():
            if not isinstance(profile_data, dict):
                logger.warning(f"Profile '{profile_name}' must be a dictionary, skipping")
                continue
            
            try:
                profile = ScanProfile(name=profile_name)
                profile.description = profile_data.get('description', '')
                
                # Parse profile-specific settings
                if 'host' in profile_data:
                    profile.host = str(profile_data['host'])
                
                if 'ports' in profile_data:
                    profile.ports = self._parse_ports(profile_data['ports'])
                
                # Numeric settings with validation
                if 'timeout' in profile_data:
                    try:
                        profile.timeout = max(0.1, float(profile_data['timeout']))
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid timeout in profile '{profile_name}': {profile_data['timeout']}")
                
                if 'workers' in profile_data:
                    try:
                        profile.workers = max(1, min(1000, int(profile_data['workers'])))
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid workers in profile '{profile_name}': {profile_data['workers']}")
                
                if 'host_concurrency' in profile_data:
                    try:
                        profile.host_concurrency = max(1, min(100, int(profile_data['host_concurrency'])))
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid host_concurrency in profile '{profile_name}': {profile_data['host_concurrency']}")
                
                # Boolean settings
                for bool_key in ['enable_banner', 'show_closed', 'ping_sweep', 'enable_udp']:
                    if bool_key in profile_data:
                        setattr(profile, bool_key, bool(profile_data[bool_key]))
                
                # String settings with validation
                if 'output_format' in profile_data:
                    fmt = profile_data['output_format']
                    if fmt in self.VALID_OUTPUT_FORMATS:
                        profile.output_format = fmt
                    else:
                        logger.warning(f"Invalid output_format in profile '{profile_name}': {fmt}")
                
                if 'log_level' in profile_data:
                    level = str(profile_data['log_level']).upper()
                    if level in self.VALID_LOG_LEVELS:
                        profile.log_level = level
                    else:
                        logger.warning(f"Invalid log_level in profile '{profile_name}': {level}")
                
                profiles[profile_name] = profile
                logger.debug(f"Loaded profile '{profile_name}': {profile.description}")
                
            except Exception as e:
                logger.error(f"Failed to load profile '{profile_name}': {e}")
        
        return profiles
    
    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file with profile support"""
        # Start with hard-coded defaults
        merged_config = self.DEFAULT_CONFIG.copy()
        
        # Find and parse configuration file
        config_file = self.find_config_file(config_path)
        if config_file:
            try:
                raw_config = self._parse_file(config_file)
                if raw_config:
                    # Validate and merge defaults
                    validated_defaults = self._validate_config(raw_config)
                    merged_config.update(validated_defaults)
                    
                    # Load profiles
                    self.profiles = self._load_profiles(raw_config)
                    
                    logger.info(f"Loaded configuration from {config_file}")
                    logger.info(f"Found {len(self.profiles)} profiles: {list(self.profiles.keys())}")
                    
            except Exception as e:
                logger.error(f"Failed to load configuration: {e}")
        
        self.loaded_config = merged_config
        return merged_config
    
    def get_profile_config(self, profile_name: str, base_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get configuration with profile settings applied"""
        if base_config is None:
            base_config = self.loaded_config.copy()
        else:
            base_config = base_config.copy()
        
        if profile_name not in self.profiles:
            logger.warning(f"Profile '{profile_name}' not found")
            return base_config
        
        profile = self.profiles[profile_name]
        profile_dict = profile.to_dict()
        
        # Apply profile settings over base config
        base_config.update(profile_dict)
        
        logger.info(f"Applied profile '{profile_name}': {profile.description}")
        return base_config
    
    def list_profiles(self) -> Dict[str, str]:
        """Get list of available profiles with descriptions"""
        return {name: profile.description for name, profile in self.profiles.items()}
    
    def get_profile(self, name: str) -> Optional[ScanProfile]:
        """Get a specific profile by name"""
        return self.profiles.get(name)
    
    def create_default_config_file(self, path: Optional[str] = None) -> str:
        """Create a sample configuration file"""
        if path is None:
            # Create in current directory
            path = "config.yaml"
        
        sample_config = {
            'defaults': {
                'timeout': 1.5,
                'workers': 200,
                'host_concurrency': 20,
                'enable_banner': True,
                'show_closed': False,
                'ping_sweep': True,
                'output_format': 'json',
                'log_level': 'INFO'
            },
            'profiles': {
                'quick-dev': {
                    'description': 'Quick scan for common development ports',
                    'ports': [3000, 3001, 5000, 8000, 8080, 9000],
                    'enable_banner': True
                },
                'web-audit': {
                    'description': 'Scan for common web server and management ports',
                    'ports': [80, 443, 8080, 8443, 8000, 3000, 22, 21, 23],
                    'timeout': 2.0,
                    'enable_banner': True
                },
                'full-tcp': {
                    'description': 'Scan all TCP ports (WARNING: Very slow!)',
                    'ports': '1-65535',
                    'workers': 50,
                    'timeout': 3.0,
                    'enable_banner': False,
                    'show_closed': False,
                    'ping_sweep': False
                },
                'local-deep': {
                    'description': 'Deep scan of localhost with process and environment info',
                    'host': 'localhost',
                    'ports': '1-10000',
                    'enable_banner': True,
                    'show_closed': True
                }
            }
        }
        
        try:
            if YAML_AVAILABLE and path.endswith('.yaml'):
                with open(path, 'w', encoding='utf-8') as f:
                    yaml.dump(sample_config, f, default_flow_style=False, allow_unicode=True)
            else:
                # Fallback to JSON
                if not path.endswith('.json'):
                    path = path.replace('.yaml', '.json')
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(sample_config, f, indent=2)
            
            logger.info(f"Created sample configuration file: {path}")
            return path
            
        except Exception as e:
            logger.error(f"Failed to create configuration file: {e}")
            raise

# Global instance for easy access
config_loader = ConfigurationLoader()

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to load configuration"""
    return config_loader.load_config(config_path)

def get_profile_config(profile_name: str, base_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convenience function to get profile configuration"""
    return config_loader.get_profile_config(profile_name, base_config)

def list_profiles() -> Dict[str, str]:
    """Convenience function to list available profiles"""
    return config_loader.list_profiles()

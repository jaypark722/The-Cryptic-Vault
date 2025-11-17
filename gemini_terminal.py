"""
Static Terminal Command Interpreter for Cryptic Vault SSH Honeypot.

This module provides a fully static, script-based command interpreter that simulates
a Linux terminal without external API dependencies. Responses are hardcoded to create
a realistic attack chain experience.
"""

import os
import time
import logging
import asyncio
import textwrap
from typing import Dict, List, Optional, Tuple

from ssh_config import COMMAND_TIMEOUT

logger = logging.getLogger(__name__)

# Global dictionary mapping exact commands to their hardcoded outputs
STATIC_COMMAND_MAP = {
    "whoami": "root",
    
    "netstat -tulpn": """tcp   0.0.0.0:22      0.0.0.0:*      LISTEN    423/sshd
tcp   0.0.0.0:5000    0.0.0.0:*      LISTEN    891/python3
tcp   0.0.0.0:80      0.0.0.0:*      LISTEN    1145/nginx""",
    
    "ps aux | grep 891": "root       891  python3 /var/www/cryptic-vault/app.py",
    
    "find /var/www/cryptic-vault -name \"*.db\" 2>/dev/null": """/var/www/cryptic-vault/database/users.db
/var/www/cryptic-vault/database/honeypot_logs.db""",
    
    "ls -la /var/www/cryptic-vault/static/data": """total 12
drwxr-xr-x 2 root root 4096 Nov 4 12:00 .
drwxr-xr-x 4 root root 4096 Nov 4 12:00 ..
-rw-r--r-- 1 root root 2884 Nov 4 12:45 cryptic.xlsx""",
    
    "cat /var/www/cryptic-vault/static/data/cryptic.xlsx": """Payment Processor Report (Q3 2025)
Card_Number,Name,Expiry,CVV,Email
4012-7345-8901-2345,Elias Vance,11/26,981,elias.vance@securemail.net
4567-8901-2345-6789,Lana Reyes,07/28,342,lana.reyes@vaultdata.org
5123-4567-8901-2345,Omar Hassan,04/27,675,omar.hassan@encrypted.io
5567-8901-2345-6789,Sofia Chen,01/29,109,sofia.chen@datasec.com
4201-9876-5432-1098,David Kim,09/26,712,david.kim@privatecorp.net
5401-2345-6789-0123,Maria Santos,03/27,428,maria.santos@techmail.com
4539-8765-4321-0987,James Park,12/28,891,james.park@businessnet.io
5234-5678-9012-3456,Aisha Patel,06/26,234,aisha.patel@globalbank.com
4916-7890-1234-5678,Carlos Rivera,08/29,567,carlos.rivera@cryptovault.net
5512-3456-7890-1234,Yuki Tanaka,02/27,890,yuki.tanaka@securedata.jp
4024-6789-0123-4567,Emma Johnson,10/26,123,emma.johnson@privatepay.com
5401-0987-6543-2109,Ahmed Al-Rashid,05/28,456,ahmed.alrashid@middleeastbank.sa
4532-1098-7654-3210,Nina Kowalski,04/27,789,nina.kowalski@eurofinance.pl
5123-9876-5432-1098,Raj Malhotra,11/29,012,raj.malhotra@indiapay.in
4716-5432-1098-7654,Sarah Mitchell,01/27,345,sarah.mitchell@usabank.com
5567-2109-8765-4321,Chen Wei,09/28,678,chen.wei@asiapayments.cn
4012-3456-7890-1234,Isabella Costa,07/26,901,isabella.costa@brazilfinance.br
5234-8901-2345-6789,David O'Brien,12/27,234,david.obrien@irishbank.ie
4539-0123-4567-8901,Fatima Hassan,03/29,567,fatima.hassan@africapay.eg
5401-4567-8901-2345,Lucas Schmidt,06/27,890,lucas.schmidt@deutschebank.de
4321-8765-4321-0987,Dmitri Volkov,11/27,123,dmitri.volkov@rusbank.ru
5234-1234-5678-9012,Priya Sharma,05/29,456,priya.sharma@indiatech.in
4012-5678-9012-3456,Jean Dupont,02/28,789,jean.dupont@eurobank.fr
5567-3456-7890-1234,Kenji Yamamoto,09/27,012,kenji.yamamoto@tokyofinance.jp
4716-9012-3456-7890,Hassan Mohamed,12/28,345,hassan.mohamed@africapay.eg
5401-8901-2345-6789,Anastasia Volkov,08/26,678,anastasia.volkov@eubank.ru
4012-1234-5678-9012,Miguel Rodriguez,11/29,901,miguel.rodriguez@latampay.ar
5123-5678-9012-3456,Li Wei,02/27,234,li.wei@asiafinance.cn
4539-6789-0123-4567,Fatima Al-Sayed,05/28,567,fatima.alsayed@gulfbank.qa
5234-7890-1234-5678,Henrik Larsson,09/26,890,henrik.larsson@nordicpay.se
4916-8901-2345-6789,Amara Okafor,12/29,123,amara.okafor@westafricabank.ng
5512-9012-3456-7890,Raj Patel,04/27,456,raj.patel@mumbaifinance.in
4024-0123-4567-8901,Elena Popescu,07/28,789,elena.popescu@romaniabank.ro
5401-1234-5678-9012,Takeshi Nakamura,10/26,012,takeshi.nakamura@osakapay.jp
4532-2345-6789-0123,Sofia Gonzalez,01/29,345,sofia.gonzalez@madridbank.es
5123-3456-7890-1234,Omar Farouk,03/27,678,omar.farouk@cairofinance.eg
4716-4567-8901-2345,Anna Kowalczyk,06/28,901,anna.kowalczyk@warsawpay.pl
5567-5678-9012-3456,Mohammed Rashid,09/29,234,mohammed.rashid@dubaibank.ae
4012-6789-0123-4567,Ingrid Schmidt,12/26,567,ingrid.schmidt@berlinfinance.de
5234-7890-1234-5678,Carlos Mendes,02/28,890,carlos.mendes@lisbonpay.pt
4539-8901-2345-6789,Yuki Sato,05/27,123,yuki.sato@yokohamabank.jp
5401-9012-3456-7890,Fatima Nasser,08/29,456,fatima.nasser@beirutfinance.lb
4321-0123-4567-8901,Pierre Dubois,11/26,789,pierre.dubois@parisbank.fr
5234-1234-5678-9012,Aisha Mohammed,01/28,012,aisha.mohammed@lagosbank.ng
4012-2345-6789-0123,Dmitri Ivanov,04/29,345,dmitri.ivanov@moscowpay.ru
5567-3456-7890-1234,Maria Fernandez,07/27,678,maria.fernandez@barcelonabank.es
4716-4567-8901-2345,Chen Li,10/28,901,chen.li@shanghaifinance.cn
5234-5678-9012-3456,Hassan Ibrahim,01/26,234,hassan.ibrahim@riyadhbank.sa
4987-6789-0123-4567,Isabella Romano,04/28,567,isabella.romano@romebank.it
5123-7890-1234-5678,Youssef Mansour,07/29,890,youssef.mansour@alexandriapay.eg
4012-8901-2345-6789,Svetlana Petrov,10/27,123,svetlana.petrov@kievfinance.ua
5401-9012-3456-7890,Ahmed Khalil,12/28,456,ahmed.khalil@ammanbank.jo
4539-0123-4567-8901,Natalia Santos,03/26,789,natalia.santos@saopaulopay.br
5234-1234-5678-9012,Raj Kumar,06/29,012,raj.kumar@delhifinance.in
4916-2345-6789-0123,Elena Martinez,09/27,345,elena.martinez@valenciabank.es
5512-3456-7890-1234,Omar Hassan,12/26,678,omar.hassan@istanbulpay.tr
4024-4567-8901-2345,Anna Nowak,02/29,901,anna.nowak@krakowbank.pl
5401-5678-9012-3456,Mohammed Ali,05/28,234,mohammed.ali@baghdadfinance.iq
4532-6789-0123-4567,Sofia Andersen,08/27,567,sofia.andersen@copenhagenbank.dk
5123-7890-1234-5678,David Cohen,11/29,890,david.cohen@telavivpay.il
4716-8901-2345-6789,Fatima Zahra,01/28,123,fatima.zahra@casablancabank.ma
5567-9012-3456-7890,Viktor Horvath,04/27,456,viktor.horvath@budapestfinance.hu
4012-0123-4567-8901,Maria Silva,07/29,789,maria.silva@lisbonbank.pt
5234-1234-5678-9012,Hassan Ahmed,10/26,012,hassan.ahmed@khartoumfinance.sd
4539-2345-6789-0123,Anastasia Ivanova,12/28,345,anastasia.ivanova@minsk.by""",
    
    "head -n 50 /var/www/cryptic-vault/static/data/cryptic.xlsx": """Payment Processor Report (Q3 2025)
Card_Number,Name,Expiry,CVV,Email
4012-7345-8901-2345,Elias Vance,11/26,981,elias.vance@securemail.net
4567-8901-2345-6789,Lana Reyes,07/28,342,lana.reyes@vaultdata.org
5123-4567-8901-2345,Omar Hassan,04/27,675,omar.hassan@encrypted.io
5567-8901-2345-6789,Sofia Chen,01/29,109,sofia.chen@datasec.com
4201-9876-5432-1098,David Kim,09/26,712,david.kim@privatecorp.net
5401-2345-6789-0123,Maria Santos,03/27,428,maria.santos@techmail.com
4539-8765-4321-0987,James Park,12/28,891,james.park@businessnet.io
5234-5678-9012-3456,Aisha Patel,06/26,234,aisha.patel@globalbank.com
4916-7890-1234-5678,Carlos Rivera,08/29,567,carlos.rivera@cryptovault.net
5512-3456-7890-1234,Yuki Tanaka,02/27,890,yuki.tanaka@securedata.jp
4024-6789-0123-4567,Emma Johnson,10/26,123,emma.johnson@privatepay.com
5401-0987-6543-2109,Ahmed Al-Rashid,05/28,456,ahmed.alrashid@middleeastbank.sa
4532-1098-7654-3210,Nina Kowalski,04/27,789,nina.kowalski@eurofinance.pl
5123-9876-5432-1098,Raj Malhotra,11/29,012,raj.malhotra@indiapay.in
4716-5432-1098-7654,Sarah Mitchell,01/27,345,sarah.mitchell@usabank.com
5567-2109-8765-4321,Chen Wei,09/28,678,chen.wei@asiapayments.cn
4012-3456-7890-1234,Isabella Costa,07/26,901,isabella.costa@brazilfinance.br
5234-8901-2345-6789,David O'Brien,12/27,234,david.obrien@irishbank.ie
4539-0123-4567-8901,Fatima Hassan,03/29,567,fatima.hassan@africapay.eg
5401-4567-8901-2345,Lucas Schmidt,06/27,890,lucas.schmidt@deutschebank.de
4321-8765-4321-0987,Dmitri Volkov,11/27,123,dmitri.volkov@rusbank.ru
5234-1234-5678-9012,Priya Sharma,05/29,456,priya.sharma@indiatech.in
4012-5678-9012-3456,Jean Dupont,02/28,789,jean.dupont@eurobank.fr
5567-3456-7890-1234,Kenji Yamamoto,09/27,012,kenji.yamamoto@tokyofinance.jp""",
    
    "wc -l /var/www/cryptic-vault/static/data/cryptic.xlsx": "50272 /var/www/cryptic-vault/static/data/cryptic.xlsx",
    
    "exit": """logout
Connection to localhost closed."""
}

class GeminiTerminal:
    """
    Manages a simulated Linux terminal using static command mappings.
    Maintains session state and provides realistic terminal responses.
    """
    
    def __init__(self, session_id: str):
        """
        Initialize a new terminal session.
        
        Args:
            session_id: Unique identifier for this terminal session
        """
        self.session_id = session_id
        self.session_start = time.time()
        self.current_directory = "/root"
        self.command_history: List[str] = []
        
        logger.info(f"Initialized static terminal session {session_id}")
    
    def _get_static_response(self, command: str) -> Optional[str]:
        """
        Get the hardcoded response for a command.
        
        Args:
            command: The stripped command string
            
        Returns:
            Optional[str]: The hardcoded output, or None if command not found
        """
        # Try exact match first
        if command in STATIC_COMMAND_MAP:
            return self._normalize_output(STATIC_COMMAND_MAP[command])
        
        # Handle common variations and additional basic commands
        cmd_lower = command.lower()
        
        # Basic navigation commands
        if cmd_lower == "pwd":
            return self.current_directory
        
        if cmd_lower.startswith("cd "):
            return self._handle_cd(command)
        
        if cmd_lower == "ls" or cmd_lower == "ls -la" or cmd_lower == "ls -l":
            return self._handle_ls()
        
        # File operations that attackers might try
        if cmd_lower.startswith("head") and "cryptic.xlsx" in cmd_lower:
            return self._normalize_output(
                STATIC_COMMAND_MAP.get(
                    "head -n 50 /var/www/cryptic-vault/static/data/cryptic.xlsx", ""
                )
            )
        
        if cmd_lower.startswith("wc") and "cryptic.xlsx" in cmd_lower:
            return self._normalize_output(
                STATIC_COMMAND_MAP.get(
                    "wc -l /var/www/cryptic-vault/static/data/cryptic.xlsx", ""
                )
            )
        
        if cmd_lower.startswith("tail") and "cryptic.xlsx" in cmd_lower:
            return self._normalize_output(
                "4987-2345-6789-0123,Viktor Petrov,10/28,234,viktor.petrov@eastbank.ua\n"
                "5234-5678-9012-3456,Ana Garcia,03/27,567,ana.garcia@latambank.mx\n"
                "4012-6789-0123-4567,Mohammed Khan,06/29,890,mohammed.khan@arabfinance.ae"
            )
        
        # Help and info commands
        if cmd_lower in ["help", "--help", "-h"]:
            return "Available commands: ls, cd, pwd, whoami, netstat, ps, find, cat, head, tail, wc, exit"
        
        if cmd_lower == "uname -a":
            return "Linux vault-server 5.15.0-generic #1 SMP x86_64 GNU/Linux"
        
        if cmd_lower == "hostname":
            return "vault-server"
        
        if cmd_lower == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        
        # Catch-all for unknown commands
        return None

    def _normalize_output(self, s: str) -> str:
        """Normalize multi-line static output to be flush-left and consistent.

        - Removes common leading indentation across lines (dedent)
        - Normalizes newlines to \n
        - Strips a single leading blank line if present
        """
        if not isinstance(s, str):
            return s
        # Dedent while preserving intended inner spacing
        s = textwrap.dedent(s)
        # Normalize newlines
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        # Avoid accidental leading blank line from triple quotes
        if s.startswith("\n"):
            s = s[1:]
        return s
    
    def _handle_cd(self, command: str) -> str:
        """
        Handle directory change commands.
        
        Args:
            command: The cd command with path
            
        Returns:
            str: Empty string on success, error message on failure
        """
        parts = command.split(maxsplit=1)
        if len(parts) < 2:
            self.current_directory = "/root"
            return ""
        
        target = parts[1].strip()
        
        if target == "..":
            if self.current_directory != "/":
                self.current_directory = os.path.dirname(self.current_directory)
            return ""
        elif target.startswith("/"):
            self.current_directory = target
            return ""
        else:
            self.current_directory = os.path.join(self.current_directory, target)
            return ""
    
    def _handle_ls(self) -> str:
        """
        Handle ls command based on current directory.
        
        Returns:
            str: Directory listing
        """
        # Map of directories to their contents
        dir_contents = {
            "/root": ".ssh  .bash_history  backup",
            "/": "bin  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
            "/var": "cache  lib  local  lock  log  mail  opt  run  spool  tmp  www",
            "/var/www": "cryptic-vault  html",
            "/var/www/cryptic-vault": "app.py  database  static  templates  instance",
            "/var/www/cryptic-vault/static": "css  data  images  js",
            "/var/www/cryptic-vault/static/data": "cryptic.xlsx",
        }
        
        normalized_path = os.path.normpath(self.current_directory)
        
        if normalized_path in dir_contents:
            return dir_contents[normalized_path]
        else:
            return "ls: cannot access '" + self.current_directory + "': No such file or directory"
    
    async def execute_command(self, command: str) -> Tuple[str, bool]:
        """
        Execute a command using static mappings and return the response.
        
        Args:
            command: The command to execute
            
        Returns:
            Tuple[str, bool]: (command output, success flag)
        """
        try:
            # Strip whitespace from command
            command = command.strip()
            
            # Log command execution
            logger.info(f"Session {self.session_id}: Executing command '{command}'")
            self.command_history.append(command)
            
            # Add realistic delay to simulate processing (0.3-0.8 seconds)
            import random
            delay = random.uniform(0.3, 0.8)
            await asyncio.sleep(delay)
            
            # Check for exit command
            if command.lower() == "exit" or command.lower() == "logout":
                response = STATIC_COMMAND_MAP.get("exit", "logout\nConnection to localhost closed.")
                return response, True
            
            # Get static response
            response = self._get_static_response(command)
            
            if response is not None:
                logger.debug(f"Static response found for '{command}'")
                return response, True
            else:
                # Command not recognized - return realistic error
                logger.debug(f"No static response for '{command}', returning error")
                cmd_name = command.split()[0] if command else "command"
                return f"{cmd_name}: command not found", False
            
        except Exception as e:
            logger.error(f"Error executing command '{command}': {str(e)}")
            return f"Command failed: {str(e)}", False
    
    def get_session_info(self) -> Dict[str, any]:
        """
        Get information about the current session.
        
        Returns:
            Dict containing session metadata
        """
        return {
            "session_id": self.session_id,
            "start_time": self.session_start,
            "duration": time.time() - self.session_start,
            "command_count": len(self.command_history),
            "current_directory": self.current_directory
        }

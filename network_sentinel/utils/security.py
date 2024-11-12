import os
import stat
import pwd
import grp

def drop_privileges():
    """Drop root privileges after capturing interface"""
    if os.geteuid() != 0:
        return

    # Get SUDO_UID and SUDO_GID from environment
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')
    
    if sudo_uid is None:
        return

    # Convert to integer
    sudo_uid = int(sudo_uid)
    sudo_gid = int(sudo_gid)
    
    # Set groups
    os.setgroups([])
    os.setgid(sudo_gid)
    os.setuid(sudo_uid)
    
    # Ensure we can't regain root
    os.umask(0o077)

def secure_file_permissions(filepath):
    """Ensure secure file permissions for sensitive files"""
    os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR) 
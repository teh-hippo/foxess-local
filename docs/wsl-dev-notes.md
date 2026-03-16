# WSL Development Notes

When developing on WSL, the relay host is your Windows machine's LAN IP.
Traffic needs to be forwarded from Windows into WSL.

## Port forwarding (Windows → WSL)

WSL2 uses a NAT'd virtual network.
LAN devices can't reach WSL directly.
Windows `netsh portproxy` bridges the gap.

```powershell
# Find your WSL IP first
wsl hostname -I

# Add (from elevated PowerShell, or WSL via sudo.exe)
sudo.exe netsh interface portproxy add v4tov4 listenport=14431 listenaddress=0.0.0.0 connectport=14431 connectaddress=<WSL_IP>
sudo.exe netsh advfirewall firewall add rule name="FoxESS MITM" dir=in action=allow protocol=TCP localport=14431

# Check
netsh interface portproxy show v4tov4

# Remove
sudo.exe netsh interface portproxy delete v4tov4 listenport=14431 listenaddress=0.0.0.0
sudo.exe netsh advfirewall firewall delete rule name="FoxESS MITM"
```

## WSL IP changes on restart

Update the port proxy when WSL restarts:

```bash
hostname -I | awk '{print $1}'
```

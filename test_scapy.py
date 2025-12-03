from scapy.all import sniff, conf, get_if_list
import time

print("=" * 70)
print("🔍 SCAPY PACKET CAPTURE TEST")
print("=" * 70)

# Show all interfaces
print("\n📡 Available Network Interfaces:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces, 1):
    print(f"  {i}. {iface}")

# Try to find Wi-Fi interface
print("\n🎯 Looking for Wi-Fi interface...")
wifi_iface = None
for iface in interfaces:
    if "Wi-Fi" in iface or "Wireless" in iface or "802.11" in iface:
        wifi_iface = iface
        print(f"✓ Found: {iface}")
        break

if not wifi_iface:
    print("❌ Wi-Fi interface not found! Using first interface...")
    wifi_iface = interfaces[0] if interfaces else None

if not wifi_iface:
    print("❌ FATAL: No network interfaces found!")
    exit(1)

# Test packet capture
print(f"\n🚀 Starting capture on: {wifi_iface}")
print("⏳ Capturing 20 packets (timeout: 15 seconds)...\n")

try:
    packets = sniff(
        iface=wifi_iface,
        count=20,
        timeout=15,
        filter=None  # No filter - capture EVERYTHING
    )
    
    print(f"\n{'=' * 70}")
    print(f"✅ SUCCESS! Captured {len(packets)} packets")
    print(f"{'=' * 70}\n")
    
    if len(packets) > 0:
        print("📦 Sample packets:")
        for i, pkt in enumerate(packets[:5], 1):
            print(f"  {i}. {pkt.summary()}")
        print(f"\n💡 Scapy is working! Your NIDS should work now.")
    else:
        print("❌ 0 packets captured!")
        print("💡 Try:")
        print("   1. Open browser and visit google.com")
        print("   2. Run this test again")
        
except PermissionError:
    print("❌ PERMISSION DENIED!")
    print("💡 Run PowerShell as ADMINISTRATOR")
except Exception as e:
    print(f"❌ ERROR: {e}")
    print(f"💡 Try running with a different interface")

print("\n" + "=" * 70)
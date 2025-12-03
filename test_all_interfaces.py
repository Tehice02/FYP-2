from scapy.all import sniff, get_if_list, conf
import time

print("=" * 70)
print("🔍 TESTING ALL NETWORK INTERFACES")
print("=" * 70)

# Get Scapy interfaces
interfaces = get_if_list()
print(f"\n📋 Found {len(interfaces)} Scapy interfaces\n")

# Try to show interface details from conf.ifaces
print("📡 Interface Details:")
for iface_name in interfaces:
    try:
        iface_obj = conf.ifaces.get(iface_name)
        if iface_obj:
            print(f"  - {iface_name}")
            print(f"    Description: {getattr(iface_obj, 'description', 'N/A')}")
            print(f"    IP: {getattr(iface_obj, 'ip', 'N/A')}")
    except:
        print(f"  - {iface_name}")
print("-" * 70)

# Test each interface
for i, iface in enumerate(interfaces, 1):
    print(f"\n{'=' * 70}")
    print(f"🧪 TEST {i}/{len(interfaces)}: {iface}")
    print(f"{'=' * 70}")
    
    # Skip loopback
    if "Loopback" in iface:
        print("⏭️  Skipping loopback interface")
        continue
    
    print(f"⏳ Capturing 5 packets (timeout: 5 seconds)...")
    print("   💡 Open browser NOW and visit google.com!")
    
    try:
        packets = sniff(
            iface=iface,
            count=5,
            timeout=5,
            filter=None
        )
        
        if len(packets) > 0:
            print(f"✅ SUCCESS! Captured {len(packets)} packets")
            print("📦 Sample packets:")
            for j, pkt in enumerate(packets[:3], 1):
                print(f"  {j}. {pkt.summary()}")
            print(f"\n🎯 THIS IS YOUR ACTIVE INTERFACE: {iface}")
            print(f"   Copy this for your NIDS!")
            break  # Found it!
        else:
            print(f"❌ No packets captured")
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    time.sleep(1)

print("\n" + "=" * 70)
print("✅ Test complete!")
print("=" * 70)
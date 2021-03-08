#!/bin/bash

echo "### MC^2 Kernel Environment Setup Script ###"
echo "Run this as sudo! Press enter to confirm..."
read

# For make, gcc, and other kernel build dependencies
apt install -y build-essential flex bison libssl-dev

cp MC2_CONFIG_TEMPLATE .config
# CPU family 17h (23) is Zen/Zen+/Zen 2
# Zen 2 is distinguishable by its AMD QoS Extensions support (advertised as CAT).
if ! grep -q "cpu family:\t23" /proc/cpuinfo; then
    if ! grep -q "cat" /proc/cpuinfo; then
        echo "*** It appears you do not have an AMD Zen 2 system!"
        echo "*** Page coloring is not supported!"
        echo "*** Disabling!"
        sed -i "s/numa=fake=2U//g" .config
    fi
fi

echo "Kernel build environment setup complete!"
echo "See MC2_README for additional setup instructions."

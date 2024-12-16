# RISC-V DM Jtag Analyzer

![Showcase](/docs/showcase.png?raw=true)

This plugin is capable of decoding JTAG Debug Module's Interface instructions. At the moment, only DMI (0x11) is supported, as that was only instruction I needed.

For this HLA to work, you need to compile low-level JTAG Analyer with HLA/Frame Version 2 support. You can find such modification in [this fork](https://github.com/tylerjsmith/jtag-analyzer).
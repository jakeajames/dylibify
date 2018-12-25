clang -isysroot /var/theos/sdks/*.sdk main.m -framework Foundation -fobjc-arc -o dylibify
echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>platform-application</key><true/></dict></plist>' > /tmp/ENTS.xml
ldid -S/tmp/ENTS.xml dylibify
rm /tmp/ENTS.xml

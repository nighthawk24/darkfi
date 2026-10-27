#!/bin/bash
set -e

VERSION="0.4"
DIST_DIR="darkfi-${VERSION}"
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# Copy binary
cp "../../darkfi-app.exe" "${DIST_DIR}/"

# Copy assets
cp -r ../../assets "${DIST_DIR}/"

# Create README
cat > "${DIST_DIR}/README.txt" <<EOF
DarkFi App v${VERSION}

To run: double-click darkfi-app.exe
EOF

# Create ZIP
zip -r "${DIST_DIR}.zip" "${DIST_DIR}"
echo "Created: ${DIST_DIR}.zip"

# Create NSIS installer
makensis -DVERSION="${VERSION}" -DDIST_DIR="${DIST_DIR}" \
    -DOUTPUT_FILE="darkfi-win64-${VERSION}-installer.exe" \
    installer.nsi

echo "Created: darkfi-win64-${VERSION}-installer.exe"
rm -rf "${DIST_DIR}"

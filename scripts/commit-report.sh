#!/bin/bash
set -e

# Setup git
git config --global user.name "OpenMRS Bot"
git config --global user.email "infrastructure@openmrs.org"


if [[ -f report.html ]]; then
  # Delete everything except the report.html
  shopt -s extglob
  rm -rf !(report.html)

  # Rename the report to index.html
  mv report.html index.html

  # Commit the file
  git add --all
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  git commit -m "Update report: $timestamp"
else
  echo "report.html not found. Skipping cleanup and commit."
  exit 1
fi

# Push changes to the report branch
git push origin HEAD:report -f

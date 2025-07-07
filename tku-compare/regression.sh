#!/bin/bash
#
# Author: Wes Fitzpatrick
#
# For use with BMC ADDM.
# Compare new TKU patterns with old TKU patterns, optionally compare any TKU overrides.

modsdir="Dir_with_modified_overrides"
oldtkudir="old_TKU"
newtkudir="new_TKU"

echo "Gathering list of modules..."
overrides=`ls $modsdir/* | while read line; do egrep "tpl [0-9].[0-9] module " "$line" | cut -f4 -d" "; done`
oldmodules=`ls $oldtkudir/* | while read line; do egrep "tpl [0-9].[0-9] module " "$line" | cut -f4 -d" "; done`
newmodules=`ls $newtkudir/* | while read line; do egrep "tpl [0-9].[0-9] module " "$line" | cut -f4 -d" "; done`

echo "Comparing Old TKU patterns against New..."
for module in `ls $oldtkudir/* | while read line; do egrep "tpl [0-9].[0-9] module " "$line" | cut -f4 -d" "; done`; do
    override=`grep " $module" $modsdir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    oldmodulefile=`grep " $module" $oldtkudir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    newmodulefile=`grep " $module" $newtkudir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    #echo "Comparing $oldmodulefile and $newmodulefile..."
    diff -q "$oldmodulefile" "$newmodulefile" >> diff_q.txt
    echo "===== Old TKU: $oldmodulefile / New TKU: $newmodulefile =====" >> diff.txt
    diff "$oldmodulefile" "$newmodulefile" >> diff.txt
    # echo "Checking $override in Overrides..."
    if [ -n "$override" ]; then
        echo "$module, Override: $override, Old TKU: $oldmodulefile, New TKU: $newmodulefile" >> overrides.txt
    fi
    if [ -z "$newmodulefile" ]; then
        echo "$module, $oldmodulefile missing from New TKU" >> missing.txt
    fi
done

echo "Checking Override patterns against Old/New..."
for module in `ls $modsdir/* | while read line; do egrep "tpl [0-9].[0-9] module " "$line" | cut -f4 -d" "; done`; do
    override=`grep " $module" $modsdir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    oldmodulefile=`grep " $module" $oldtkudir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    newmodulefile=`grep " $module" $newtkudir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    if [ -z "$oldmodulefile" ]; then
        echo "$module, $override missing has no TKU in Old" >> missing.txt
    fi
    if [ -z "$newmodulefile" ]; then
        echo "$module, $override missing has no TKU in Old" >> missing.txt
    fi
done

echo "Checking for New patterns..."
for module in `ls $newtkudir/* | while read line; do egrep "tpl [0-9].[0-9] module " "$line" | cut -f4 -d" "; done`; do
    oldmodulefile=`grep " $module" $oldtkudir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    newmodulefile=`grep " $module" $newtkudir/* | egrep "tpl [0-9]" | cut -f1 -d:`
    if [ -z "$oldmodulefile" ]; then
        echo "$module, $newmodulefile is new (not in Old TKU)" >> missing.txt
    fi
done
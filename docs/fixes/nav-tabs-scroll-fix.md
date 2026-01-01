# Nav Tabs Horizontal Scroll Fix

## Issue
The navigation tabs on the Scan Findings page required horizontal scrolling to access all menu items (Home, Subdomains, Screenshots, URLs dropdown, etc.). This was inconsistent with other dropdown menus like Settings which displayed properly without scrolling.

## Root Cause
Three problems were identified:

1. **HTML wrapper**: The nav tabs were wrapped in `<div class="overflow-x-auto">` which forced horizontal scrolling
2. **CSS flex-nowrap**: The class `flex-nowrap` on the `<ul>` element prevented tabs from wrapping
3. **Global CSS rules**: In `responsive.css`, there were global rules forcing all `.nav-tabs` to use `flex-wrap: nowrap` and `overflow-x: auto`

## Solution

### 1. HTML Fix (`startScan/templates/startScan/detail_scan.html`)
- Removed the `<div class="overflow-x-auto">` wrapper
- Removed `flex-nowrap` class from the nav tabs `<ul>`
- Changed dropdown menu inline style from `width: 240px` to `min-width: 240px; max-height: none`

### 2. CSS Fix (`static/custom/responsive.css`)
Changed the global nav-tabs rules:

**Before:**
```css
.nav-tabs {
  flex-wrap: nowrap;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
}
```

**After:**
```css
.nav-tabs {
  flex-wrap: wrap;
}

.nav-tabs .dropdown-menu {
  max-height: none !important;
  overflow-y: visible !important;
}
```

## Files Modified
- `web/startScan/templates/startScan/detail_scan.html`
- `web/static/custom/responsive.css`

## Date
January 2026

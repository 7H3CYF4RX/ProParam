# ProParam - User Interface Guide

**Author:** Muhammed Farhan (7H3CYF4RX)

---

## 🎨 ProParam Interface Overview

ProParam features a **modern, professional 5-panel tabbed interface** designed for efficient security testing workflow.

---

## 📊 Interface Panels

### 1. **Dashboard Tab** ⭐

The main landing page showing overview and quick actions.

#### **Header Section:**
```
┌────────────────────────────────────────────────┐
│  ProParam                                      │
│  Version 1.0.0 - Cache Poisoning Detection &  │
│  Parameter Discovery                           │
└────────────────────────────────────────────────┘
```

#### **Statistics Panel:**
Displays real-time scan metrics in a 2x3 grid:

| Total Scans | Active Scans | Parameters Found |
|-------------|--------------|------------------|
| **0** | **0** | **0** |

| **Cache Issues** | **High Severity** | **Medium Severity** |
|------------------|-------------------|---------------------|
| **0** | **0** | **0** |

#### **Quick Actions Panel:**
6 buttons for common operations:

**Row 1:**
- 🔍 **View Scan Results** → Jump to Results tab
- 📊 **View Cache Analysis** → Jump to Cache tab
- ⚙️ **Open Configuration** → Jump to Settings

**Row 2:**
- 💾 **Export Results** → Save findings to file
- 🗑️ **Clear Results** → Reset all data
- ❓ **Help & Documentation** → Show help dialog

---

### 2. **Scan Results Tab** 📋

Professional data table showing all findings.

#### **Table Columns:**

| Column | Description | Example |
|--------|-------------|---------|
| **Name** | Parameter/header name | `debug`, `api_key` |
| **Type** | Discovery method | Query, POST, Header, JSON |
| **Evidence** | Why it was flagged | "Response +500 bytes" |
| **Severity** | Risk level | 🔴 CRITICAL, 🔴 HIGH, 🟠 MEDIUM, 🔵 LOW, ⚪ INFO |
| **Cached** | Cache status | Yes / No |

#### **Color Coding:**
- 🔴 **RED** - Critical & High severity
- 🟠 **ORANGE** - Medium severity  
- 🔵 **BLUE** - Low severity
- ⚪ **GRAY** - Informational

#### **Features:**
- ✅ Sortable columns (click headers)
- ✅ Right-click context menu:
  - View Details
  - Generate PoC
  - Send to Repeater
  - Delete

#### **Sample Data:**
```
┌──────────┬─────────┬──────────────────────┬──────────┬────────┐
│ Name     │ Type    │ Evidence             │ Severity │ Cached │
├──────────┼─────────┼──────────────────────┼──────────┼────────┤
│ debug    │ Query   │ Response +500 bytes  │ HIGH     │ Yes    │
│ api_key  │ Header  │ Reflection detected  │ CRITICAL │ No     │
│ callback │ JSON    │ Different response   │ MEDIUM   │ Yes    │
│ admin    │ Query   │ Status 200→403       │ HIGH     │ No     │
└──────────┴─────────┴──────────────────────┴──────────┴────────┘
```

---

### 3. **Cache Analysis Tab** 🔍

Visual representation of cache behavior and vulnerabilities.

#### **Cache Information Section:**

```
┌─────────────────────────────────────────────────────┐
│ Cache System:  Cloudflare ✓                        │
│ Cache Status:  ✓ Cached (GREEN)                    │
│ TTL:           1 hour (3600 seconds)                │
└─────────────────────────────────────────────────────┘
```

#### **Cache Headers Box:**
```
┌─────────────────────────────────────────────────────┐
│ Cache Headers:                                      │
│                                                     │
│ cf-cache-status: HIT                               │
│ cache-control: public, max-age=3600                │
│ age: 1234                                          │
│ x-cache: HIT                                       │
└─────────────────────────────────────────────────────┘
```

#### **Cache Key Components:**

**Left Panel - Keyed (✓ Included):**
```
┌──────────────────────────────┐
│ Keyed Components             │
│ (Included in Cache Key)      │
├──────────────────────────────┤
│ ✓ URL Path                   │
│ ✓ Query String               │
│ ✓ Host Header                │
│ ✓ Accept-Encoding            │
└──────────────────────────────┘
```

**Right Panel - Unkeyed (✗ NOT Included):**
```
┌──────────────────────────────┐
│ Unkeyed Components           │
│ (NOT in Cache Key)           │
├──────────────────────────────┤
│ ✗ X-Forwarded-Host   ⚠️      │
│ ✗ X-Original-URL     ⚠️      │
│ ✗ X-Forwarded-For    ⚠️      │
└──────────────────────────────┘
```

#### **Analysis Notes:**
```
┌─────────────────────────────────────────────────────┐
│ Analysis Notes:                                     │
│                                                     │
│ Cache system successfully identified: Cloudflare   │
│ Response is being cached with 1 hour TTL          │
│                                                     │
│ ⚠️  WARNING: Unkeyed components detected!         │
│ These inputs affect the response but are not      │
│ part of the cache key. This could lead to cache   │
│ poisoning vulnerabilities.                        │
│                                                     │
│ Recommendation: Test these headers for cache      │
│ poisoning potential.                              │
└─────────────────────────────────────────────────────┘
```

---

### 4. **Configuration Tab** ⚙️

Comprehensive settings panel with organized sections.

#### **Scan Settings:**
```
┌─────────────────────────────────────────────┐
│ Thread Count:        [====10====]     (1-50) │
│ Request Delay (ms):  [==100===]    (0-5000) │
│                                             │
│ ☑ Follow Redirects                         │
│ ☑ In-Scope Only                            │
└─────────────────────────────────────────────┘
```

#### **Discovery Settings:**
```
┌─────────────────────────────────────────────┐
│ Wordlist Tier:  [Normal ▼]                 │
│                  Fast (100 params)          │
│                  Normal (500 params) ✓      │
│                  Deep (2000 params)         │
│                  Exhaustive (5000+ params)  │
│                                             │
│ ☑ Include Headers                          │
│ ☑ Include Cookies                          │
│ ☑ Include JSON Parameters                  │
│ ☑ Include XML Parameters                   │
│                                             │
│ Max Parameters to Test: [1000]             │
└─────────────────────────────────────────────┘
```

#### **Cache Poisoning Detection:**
```
┌─────────────────────────────────────────────┐
│ ☑ Enable Cache Analysis                    │
│ ☑ Auto-Verify Findings                     │
│                                             │
│ Cache Stability Tests: [===3===]     (1-10) │
│                                             │
│ Detection Modules:                          │
│ ☑ Detect Unkeyed Headers                   │
│ ☑ Detect Parameter Cloaking                │
│ ☑ Detect Fat GET                           │
│ ☑ Detect Cache Deception                   │
└─────────────────────────────────────────────┘
```

#### **Reporting Settings:**
```
┌─────────────────────────────────────────────┐
│ ☑ Auto-Generate PoCs                       │
│ ☑ Create Burp Issues                       │
│                                             │
│ Min Severity to Report: [Medium ▼]         │
│                         INFO               │
│                         LOW                │
│                         MEDIUM ✓           │
│                         HIGH               │
│                         CRITICAL           │
└─────────────────────────────────────────────┘
```

#### **Action Buttons:**
```
┌─────────────────────────────────────────────┐
│  [Save Configuration]  [Load Configuration] │
│              [Reset to Defaults]            │
└─────────────────────────────────────────────┘
```

---

### 5. **Logs Tab** 📝

Real-time activity log with filterable output.

```
┌──────────────────────────────────────────────────────────┐
│ [2025-12-03 13:40:15] ProParam extension loaded         │
│ [2025-12-03 13:41:02] Started scan: https://example.com │
│ [2025-12-03 13:41:05] Testing 500 parameters...        │
│ [2025-12-03 13:41:15] Found parameter: debug (HIGH)    │
│ [2025-12-03 13:41:20] Found parameter: api_key (CRIT)  │
│ [2025-12-03 13:41:35] Cache system detected: Cloudflare│
│ [2025-12-03 13:41:40] Unkeyed header found: X-F-Host  │
│ [2025-12-03 13:41:45] Scan completed: 5 findings      │
│                                                         │
│                     [Clear Logs]                        │
└──────────────────────────────────────────────────────────┘
```

---

## 🎯 Context Menu Integration

### **Right-Click Menu in Burp:**

When you right-click any request in Burp:

```
┌────────────────────────────────────┐
│ Send to Repeater                   │
│ Send to Intruder                   │
│ Send to Comparer                   │
│ ──────────────────────────────────│
│ ► Extensions                       │
│   ├─ Scan with ProParam       ⭐   │
│   ├─ Quick Scan (Fast mode)        │
│   ├─ Analyze Cache Behavior        │
│   └─ Test Selected Parameter       │
└────────────────────────────────────┘
```

---

## 🎨 Design Principles

### **Professional Aesthetics:**
- ✅ Dark theme matching Burp Suite
- ✅ Clean, modern layout
- ✅ Color-coded severity levels
- ✅ Consistent spacing and alignment
- ✅ Professional typography

### **User Experience:**
- ✅ **Intuitive navigation** - Logical tab order
- ✅ **Quick access** - Dashboard shortcuts
- ✅ **Visual feedback** - Real-time updates
- ✅ **Context awareness** - Right-click menus
- ✅ **Helpful tooltips** - Guidance when needed

### **Accessibility:**
- ✅ High contrast text
- ✅ Clear labeling
- ✅ Keyboard shortcuts
- ✅ Logical tab order
- ✅ Screen reader friendly

---

## 📱 Responsive Layout

The interface adapts to Burp's window size:

- **Full width**: All panels visible
- **Narrow**: Tables scroll horizontally
- **Minimum**: Core functionality preserved

---

## 🎨 Color Scheme

### **Severity Colors:**
```
CRITICAL:  #DC143C (Crimson Red)
HIGH:      #FF0000 (Red)
MEDIUM:    #FFA500 (Orange)
LOW:       #1E90FF (Blue)
INFO:      #808080 (Gray)
```

### **Status Colors:**
```
Success:   #00FF00 (Green)
Warning:   #FFA500 (Orange)
Error:     #FF0000 (Red)
Cached:    #00CED1 (Turquoise)
```

---

## 💡 Interface Highlights

### **What Makes ProParam's UI Special:**

1. **📊 Visual Cache Analysis**
   - Clear distinction between keyed/unkeyed
   - Visual warnings for vulnerabilities
   - At-a-glance cache system identification

2. **🎯 Smart Organization**
   - Logical grouping of related settings
   - Progressive disclosure (details on demand)
   - Quick actions for common tasks

3. **🔍 Powerful Results Table**
   - Sortable, filterable data
   - Color-coded priorities
   - One-click actions (PoC, Repeater)

4. **⚡ Real-Time Feedback**
   - Live statistics
   - Progress indicators
   - Activity logs

5. **🎨 Professional Polish**
   - Consistent design language
   - Smooth interactions
   - Attention to detail

---

## 🚀 Quick Interface Tour

### **First Time User Flow:**

1. **Load Extension** → See Dashboard
2. **Right-click request** → "Scan with ProParam"
3. **View Results** → Sorted by severity
4. **Click finding** → See details
5. **Generate PoC** → Copy to use
6. **Send to Repeater** → Further testing

### **Power User Flow:**

1. **Configure settings** → Set preferences
2. **Run batch scans** → Multiple targets
3. **Export results** → Save findings
4. **Review cache analysis** → Identify patterns
5. **Create Burp issues** → Document vulns

---

## 📖 Interface Documentation

See the main **README.md** for:
- Complete feature descriptions
- Usage examples  
- Configuration details
- Troubleshooting guide

---

**ProParam** - Professional Parameter Mining with a Professional Interface! 🎨

---

**Created by:** Muhammed Farhan (7H3CYF4RX)

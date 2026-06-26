# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WinMTR v0.92 — a Windows GUI application combining traceroute and ping functionality. Licensed under GPL v2. Built with C++ and MFC (Microsoft Foundation Classes).

## Build System

- **IDE**: Visual Studio (solution originated from VS 2010, `.sln` format version 11.00)
- **Solution file**: `WinMTR.sln`
- **Project file**: `WinMTR.vcxproj`
- **Configurations**: Debug/Release × Win32/x64
- **Output directories**: `Debug_x32/`, `Debug_x64/`, `Release_x32/`, `Release_x64/`
- **Character set**: MultiByte (not Unicode)
- **Runtime library**: Static linking (`/MT` for Release, `/MTd` for Debug)
- **Key preprocessor defines**: `WIN32`, `_CRT_SECURE_NO_WARNINGS`

Build via Visual Studio: open `WinMTR.sln` and build the desired configuration.

## Architecture

All source files are in the project root (flat structure, no subdirectories).

### Core Classes

- **WinMTRMain** (`WinMTRMain.h/.cpp`) — `CWinApp` subclass; application entry point, command-line parsing (`--help`, hostname, options)
- **WinMTRDialog** (`WinMTRDialog.h/.cpp`) — Main dialog window (`CDialog`). Manages UI state machine (IDLE → TRACING → STOPPING → EXIT), hosts the list control displaying trace results, timer-driven display refresh, export to text/HTML, clipboard copy
- **WinMTRNet** (`WinMTRNet.h/.cpp`) — Network tracing engine. Dynamically loads ICMP functions (`IcmpCreateFile`, `IcmpSendEcho`), manages `s_nethost` array (`MaxHost=256` hops), runs trace in a separate thread with mutex synchronization
- **WinMTRGlobal** (`WinMTRGlobal.h/.cpp`) — Global constants, ICMP defines, column definitions, `gettimeofday` implementation

### Supporting Dialogs

- **WinMTROptions** — Ping interval, size, max LRU, DNS toggle
- **WinMTRProperties** — Per-hop detail view (double-click a host)
- **WinMTRHelp/WinMTRLicense** — About/license dialogs
- **WinMTRStatusBar** — Custom status bar

### Key Constants (WinMTRGlobal.h)

- `MaxHost 256` — max traceroute hops
- `MaxSequence 32767` — max ping sequence number
- `DEFAULT_PING_SIZE 64`, `DEFAULT_INTERVAL 1.0`, `DEFAULT_MAX_LRU 128`

### Threading Model

`WinMTRNet::DoTrace` runs in a worker thread created via `_beginthread`. Access to the `s_nethost` array is protected by a `HANDLE` mutex (`ghMutex`). The dialog polls results via a Windows timer (`WINMTR_DIALOG_TIMER`).

## Important Notes

- This is a Windows-only MFC application — it cannot be compiled on macOS/Linux
- No test framework is present; there are no automated tests
- UI resources are defined in `WinMTR.rc` with IDs in `resource.h`

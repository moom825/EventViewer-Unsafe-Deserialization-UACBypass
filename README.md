# EventViewer-Unsafe-Deserialization-UACBypass

A Proof of Concept (PoC) demonstrating a User Account Control (UAC) bypass technique in Windows by exploiting the unsafe deserialization of Event Viewer's RecentFiles. This technique was discovered by orange_8361.

## Installation

This project is a Visual Studio Code project and requires Visual Studio and C# to be installed.

## Usage

1. Go to the "Releases" section of this repository.
2. Download the latest release of "EventViewerDeserializationExploit.exe."
3. Open a command prompt or PowerShell.
4. Run the exploit executable with the desired command, like:
EventViewerDeserializationExploit.exe cmd.exe


## Credits

Credits to orange_8361 for discovering and sharing this UAC bypass technique.
// console/version.h
//
// The console version lives here and nowhere else:
//   - console.rc      -> FileVersion / ProductVersion (Explorer -> Details)
//   - core/output.cpp -> `console --version` text
// Change the numbers once and rebuild; the .rc is run through the C
// preprocessor by windres, so it reads this header too.
#ifndef ROOTLAYER_CONSOLE_VERSION_H
#define ROOTLAYER_CONSOLE_VERSION_H

#define CONSOLE_VERSION_MAJOR 1
#define CONSOLE_VERSION_MINOR 0
#define CONSOLE_VERSION_PATCH 0
#define CONSOLE_VERSION_BUILD 0

// "1.0.0" for text output, "1.0.0.0" for the version resource.
#define CONSOLE_VERSION_STRING "1.0.0"
#define CONSOLE_VERSION_STRING4 "1.0.0.0"

#endif  // ROOTLAYER_CONSOLE_VERSION_H

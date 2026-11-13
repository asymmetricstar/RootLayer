// Qt Widgets status panel for the client.
//
// The tunnel (TAP, UDP relay, signaling) keeps running in its own thread; this
// process' main thread owns the Qt GUI. Call run_qt_ui() from main() after the
// tunnel thread has been started.
#ifndef P2P_UI_QT_H
#define P2P_UI_QT_H

int run_qt_ui();

#endif  // P2P_UI_QT_H

// Qt Widgets status panel: dark rounded card window with the header, the
// connection strip and the four information cards. All values come from the
// tunnel thread through the globals declared below, so the UI never blocks on
// network or TAP work.
#include "ui_qt.h"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QGuiApplication>
#include <QFont>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QPushButton>
#include <QScreen>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QVBoxLayout>
#include <QVector>

#include <atomic>
#include <cmath>
#include <functional>
#include <string>

// ------------------------------------------------------------- tunnel state
#include "shared_state.h"

namespace {

const QColor kSurface("#14181F");
const QColor kHeader("#171C26");
const QColor kBorder("#2A2F3A");
const QColor kSeparator("#242A36");
const QColor kCard("#1A202C");
const QColor kCardBorder("#232936");
const QColor kText("#EEF2F7");
const QColor kMuted("#8B94A7");
const QColor kSoft("#CBD2DF");
const QColor kGreen("#22C55E");
const QColor kGreenSoft("#6EE7B7");
const QColor kDim("#667085");
const QColor kRed("#EF4444");

const int kPanelW = 420;
const int kPanelH = 344;
const int kShadow = 12;
const int kHeaderH = 68;

enum class Icon { Globe, Clock, Activity, Shield, Wifi };

QFont ui_font(int pixel, bool bold = false) {
    QFont f("Segoe UI");
    f.setPixelSize(pixel);
    f.setBold(bold);
    return f;
}

QFont mono_font(int pixel, bool bold = true) {
    QFont f("Consolas");
    f.setStyleHint(QFont::Monospace);
    f.setPixelSize(pixel);
    f.setBold(bold);
    return f;
}

QPixmap paint_icon(Icon kind, int size, const QColor& color) {
    const qreal dpr = 2.0;
    QPixmap pm(int(size * dpr), int(size * dpr));
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QPen pen(color);
    pen.setWidthF(1.3);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);

    const qreal s = size;
    switch (kind) {
        case Icon::Globe:
            p.drawEllipse(QRectF(1.5, 1.5, s - 3, s - 3));
            p.drawEllipse(QRectF(s * 0.32, 1.5, s * 0.36, s - 3));
            p.drawLine(QPointF(1.5, s / 2), QPointF(s - 1.5, s / 2));
            break;
        case Icon::Clock:
            p.drawEllipse(QRectF(1.5, 1.5, s - 3, s - 3));
            p.drawLine(QPointF(s / 2, s / 2), QPointF(s / 2, s * 0.28));
            p.drawLine(QPointF(s / 2, s / 2), QPointF(s * 0.68, s * 0.6));
            break;
        case Icon::Activity: {
            QPainterPath path;
            path.moveTo(1, s * 0.62);
            path.lineTo(s * 0.3, s * 0.62);
            path.lineTo(s * 0.44, s * 0.24);
            path.lineTo(s * 0.58, s * 0.82);
            path.lineTo(s * 0.72, s * 0.45);
            path.lineTo(s - 1, s * 0.45);
            p.drawPath(path);
            break;
        }
        case Icon::Shield: {
            QPainterPath path;
            path.moveTo(s / 2, 1.2);
            path.lineTo(s - 2, s * 0.28);
            path.lineTo(s - 2, s * 0.55);
            path.cubicTo(s - 2, s * 0.8, s * 0.72, s * 0.95, s / 2, s - 1);
            path.cubicTo(s * 0.28, s * 0.95, 2, s * 0.8, 2, s * 0.55);
            path.lineTo(2, s * 0.28);
            path.closeSubpath();
            p.drawPath(path);
            break;
        }
        case Icon::Wifi: {
            p.drawArc(QRectF(1, s * 0.35, s - 2, s * 0.7), 30 * 16, 120 * 16);
            p.drawArc(QRectF(s * 0.24, s * 0.55, s * 0.52, s * 0.5), 30 * 16, 120 * 16);
            p.setBrush(color);
            p.drawEllipse(QPointF(s / 2, s * 0.82), s * 0.08, s * 0.08);
            break;
        }
    }
    p.end();
    return pm;
}

// Small helper that keeps a label with a leading icon.
QLabel* icon_label(Icon kind, int size, const QColor& color) {
    auto* l = new QLabel;
    l->setPixmap(paint_icon(kind, size, color));
    l->setFixedSize(size, size);
    l->setAttribute(Qt::WA_TranslucentBackground);
    return l;
}

class PulseDot : public QWidget {
public:
    explicit PulseDot(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(10, 10);
        setAttribute(Qt::WA_TranslucentBackground);
        timer_.setInterval(60);
        QObject::connect(&timer_, &QTimer::timeout, [this] {
            phase_ += 0.07;
            if (phase_ > 1.0) phase_ = 0.0;
            update();
        });
        timer_.start();
    }

    void setActive(bool active) {
        active_ = active;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(Qt::NoPen);
        const QColor base = active_ ? kGreen : kMuted;
        const double pulse = active_ ? 0.5 + 0.5 * std::sin(phase_ * 2 * M_PI) : 0.0;
        QColor halo = base;
        halo.setAlphaF(active_ ? 0.18 + 0.22 * pulse : 0.12);
        p.setBrush(halo);
        p.drawEllipse(QPointF(5, 5), 3.2 + 1.8 * pulse, 3.2 + 1.8 * pulse);
        p.setBrush(base);
        p.drawEllipse(QPointF(5, 5), 3.0, 3.0);
    }

private:
    QTimer timer_;
    double phase_ = 0.0;
    bool active_ = false;
};

// Trims fully transparent margins so the artwork can fill the tile edge to
// edge; the source PNG carries padding that made the logo look inset.
QPixmap trim_transparent(const QPixmap& source) {
    if (source.isNull()) return source;
    QImage img = source.toImage().convertToFormat(QImage::Format_ARGB32);
    int left = img.width();
    int top = img.height();
    int right = -1;
    int bottom = -1;
    for (int y = 0; y < img.height(); ++y) {
        const QRgb* row = reinterpret_cast<const QRgb*>(img.constScanLine(y));
        for (int x = 0; x < img.width(); ++x) {
            if (qAlpha(row[x]) > 16) {
                if (x < left) left = x;
                if (x > right) right = x;
                if (y < top) top = y;
                if (y > bottom) bottom = y;
            }
        }
    }
    if (right < left || bottom < top) return source;
    left = qMax(0, left - 1);
    top = qMax(0, top - 1);
    right = qMin(img.width() - 1, right + 1);
    bottom = qMin(img.height() - 1, bottom + 1);
    return source.copy(left, top, right - left + 1, bottom - top + 1);
}

// Every icon the app shows is shipped in the resources/icons folder: next to
// the executable for a deployed copy, one or two levels up for build/bin.
QString icon_path(const QString& name) {
    const QString exe = QCoreApplication::applicationDirPath();
    const QStringList roots = {
        exe + "/resources/icons/",
        exe + "/../resources/icons/",
        exe + "/../../resources/icons/",
    };
    for (const auto& root : roots) {
        const QString path = root + name;
        if (QFile::exists(path)) return path;
    }
    return QString();
}

// Header logo: the product icon from resources/icons, trimmed to its visible
// bounds and stretched to cover the whole rounded tile. Falls back to the
// painted mesh mark when the PNG is missing.
class AppLogo : public QWidget {
public:
    explicit AppLogo(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(40, 40);
        setAttribute(Qt::WA_TranslucentBackground);

        for (const char* name : {"40x40.png", "exe_client.png", "exe_client.ico"}) {
            const QString path = icon_path(name);
            if (path.isEmpty()) continue;
            QPixmap pm(path);
            if (!pm.isNull()) {
                icon_ = trim_transparent(pm);
                break;
            }
        }
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setRenderHint(QPainter::SmoothPixmapTransform);

        const QRectF tile(0.5, 0.5, 39, 39);
        QPainterPath clip;
        clip.addRoundedRect(tile, 11, 11);

        p.save();
        p.setClipPath(clip);
        if (!icon_.isNull()) {
            const QSize scaled = icon_.size().scaled(QSize(40, 40), Qt::KeepAspectRatioByExpanding);
            const QRectF target_rect(QPointF((40 - scaled.width()) / 2.0,
                                             (40 - scaled.height()) / 2.0),
                                     QSizeF(scaled));
            p.drawPixmap(target_rect, icon_, QRectF(icon_.rect()));
        } else {
            QColor tile_bg("#22C55E");
            tile_bg.setAlphaF(0.10);
            p.fillRect(QRectF(0, 0, 40, 40), tile_bg);
            const QPointF c(20, 20);
            const QPointF leaves[4] = {QPointF(9, 9), QPointF(31, 9), QPointF(9, 31), QPointF(31, 31)};
            QColor line("#22C55E");
            line.setAlphaF(0.75);
            p.setPen(QPen(line, 1.1));
            for (const auto& leaf : leaves) p.drawLine(c, leaf);
            p.setPen(Qt::NoPen);
            p.setBrush(QColor("#22C55E"));
            p.drawEllipse(c, 3.4, 3.4);
            p.setBrush(QColor("#A7F3D0"));
            for (const auto& leaf : leaves) p.drawEllipse(leaf, 2.1, 2.1);
        }
        p.restore();

        QColor outline("#22C55E");
        outline.setAlphaF(0.25);
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(outline, 1));
        p.drawRoundedRect(tile, 11, 11);
    }

private:
    QPixmap icon_;
};

class Sparkline : public QWidget {
public:
    explicit Sparkline(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedHeight(26);
        setAttribute(Qt::WA_TranslucentBackground);
    }

    // Each entry is one real measurement from IcmpSendEcho (-1 = no reply, drawn
    // as a gap instead of inventing a value).
    void push(int ms) {
        history_.append(ms);
        while (history_.size() > 24) history_.removeFirst();
        update();
    }

    void reset() {
        history_.clear();
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        if (history_.isEmpty()) return;
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        double maxv = 10.0;
        for (int v : history_) maxv = std::max(maxv, double(v));

        const double w = width();
        const double h = height();
        QPainterPath path;
        bool pen_down = false;
        for (int i = 0; i < history_.size(); ++i) {
            if (history_[i] < 0) {  // no reply: break the line
                pen_down = false;
                continue;
            }
            const double x = history_.size() == 1 ? 0.0 : (double(i) / (history_.size() - 1)) * w;
            const double y = h - 3.0 - (double(history_[i]) / maxv) * (h - 6.0);
            if (!pen_down) {
                path.moveTo(x, y);
                pen_down = true;
            } else {
                path.lineTo(x, y);
            }
        }
        QPen pen(kGreen);
        pen.setWidthF(1.8);
        pen.setCapStyle(Qt::RoundCap);
        pen.setJoinStyle(Qt::RoundJoin);
        p.setPen(pen);
        p.drawPath(path);
    }

private:
    QVector<int> history_;
};

// A card that reacts to a click (used for "click to copy the IP"). A press
// that turns into a window drag must not count as a click.
class CardFrame : public QFrame {
public:
    explicit CardFrame(QWidget* parent = nullptr) : QFrame(parent) {}
    std::function<void()> on_click;

protected:
    void mousePressEvent(QMouseEvent* event) override {
        pressed_ = event->globalPosition().toPoint();
        moved_ = false;
        QFrame::mousePressEvent(event);
    }

    void mouseMoveEvent(QMouseEvent* event) override {
        if ((event->buttons() & Qt::LeftButton) &&
            (event->globalPosition().toPoint() - pressed_).manhattanLength() > 4) {
            moved_ = true;
        }
        QFrame::mouseMoveEvent(event);
    }

    void mouseReleaseEvent(QMouseEvent* event) override {
        if (!moved_ && on_click) on_click();
        QFrame::mouseReleaseEvent(event);
    }

private:
    QPoint pressed_;
    bool moved_ = false;
};

struct Card {
    CardFrame* frame = nullptr;
    QLabel* value = nullptr;
    QLabel* sub = nullptr;
    QVBoxLayout* layout = nullptr;
};

Card make_card(const QString& title, Icon icon, const QString& value,
               const QString& sub, bool value_green, CardFrame* frame) {
    Card c;
    c.frame = frame != nullptr ? frame : new CardFrame;
    c.frame->setObjectName("card");
    c.frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    auto* layout = new QVBoxLayout(c.frame);
    layout->setContentsMargins(12, 10, 12, 10);
    layout->setSpacing(0);
    c.layout = layout;

    auto* head = new QHBoxLayout;
    head->setSpacing(6);
    head->setContentsMargins(0, 0, 0, 0);
    head->addWidget(icon_label(icon, 13, kMuted));
    auto* title_label = new QLabel(title);
    title_label->setFont(ui_font(11, true));
    title_label->setStyleSheet("color:#8B94A7; letter-spacing:0.6px;");
    head->addWidget(title_label);
    head->addStretch();
    layout->addLayout(head);

    layout->addSpacing(7);
    c.value = new QLabel(value);
    c.value->setFont(mono_font(18, true));
    c.value->setStyleSheet(value_green ? "color:#22C55E;" : "color:#EEF2F7;");
    layout->addWidget(c.value);

    c.sub = new QLabel(sub);
    c.sub->setFont(ui_font(11));
    c.sub->setStyleSheet("color:#667085;");
    layout->addSpacing(6);
    layout->addWidget(c.sub);
    layout->addStretch();
    return c;
}

QString format_uptime(long long seconds) {
    if (seconds < 0) seconds = 0;
    return QString("%1:%2:%3")
        .arg(seconds / 3600, 2, 10, QChar('0'))
        .arg((seconds / 60) % 60, 2, 10, QChar('0'))
        .arg(seconds % 60, 2, 10, QChar('0'));
}


QIcon tray_icon(bool online) {
    // The .ico files carry 16..256 px variants, so the shell picks a crisp
    // size for the notification area; the PNG stays as a fallback.
    const QString base = online ? "tray_online_tarla_ag" : "tray_offline_tarla_ag";
    for (const char* ext : {".ico", ".png"}) {
        const QString path = icon_path(base + ext);
        if (path.isEmpty()) continue;
        QIcon icon(path);
        if (!icon.isNull()) return icon;
    }
    QPixmap pm(32, 32);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(online ? kGreen : kMuted);
    p.drawEllipse(QRectF(4, 4, 24, 24));
    p.end();
    return QIcon(pm);
}

class ClientPanel : public QWidget {
public:
    ClientPanel() {
        setWindowTitle("RootLayer");
        setWindowFlags(Qt::FramelessWindowHint | Qt::Window);
        setAttribute(Qt::WA_TranslucentBackground);
        setFixedSize(kPanelW + 2 * kShadow, kPanelH + 2 * kShadow);

        auto* outer = new QVBoxLayout(this);
        outer->setContentsMargins(kShadow, kShadow, kShadow, kShadow);
        outer->setSpacing(0);

        auto* body = new QWidget;
        body->setObjectName("surface");
        body->setFixedSize(kPanelW, kPanelH);
        outer->addWidget(body);

        auto* root = new QVBoxLayout(body);
        root->setContentsMargins(0, 0, 0, 0);
        root->setSpacing(0);

        root->addWidget(build_header());
        root->addWidget(build_body(), 0, Qt::AlignTop);

        auto* timer = new QTimer(this);
        timer->setInterval(500);
        QObject::connect(timer, &QTimer::timeout, [this] { refresh(); });
        timer->start();

        auto* ping_timer = new QTimer(this);
        ping_timer->setInterval(2000);
        QObject::connect(ping_timer, &QTimer::timeout, [this] { sample_ping(); });
        ping_timer->start();

        refresh();
    }

    void set_connected(bool connected) {
        connected_ = connected;
        refresh();
    }

    bool connected() const { return connected_; }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);

        // Soft shadow behind the card.
        for (int i = kShadow; i > 0; --i) {
            QColor shadow(0, 0, 0, 6 + (kShadow - i) * 2);
            p.setPen(Qt::NoPen);
            p.setBrush(shadow);
            p.drawRoundedRect(QRectF(kShadow - i * 0.5, kShadow - i * 0.5 + 2,
                                     kPanelW + i, kPanelH + i), 16 + i * 0.5, 16 + i * 0.5);
        }

        const QRectF panel(kShadow, kShadow, kPanelW, kPanelH);
        QPainterPath clip;
        clip.addRoundedRect(panel, 16, 16);
        p.setClipPath(clip);
        p.fillRect(panel, kSurface);

        // Header band: rounded on top, square where it meets the cards.
        QPainterPath band;
        band.moveTo(panel.left(), panel.top() + kHeaderH);
        band.lineTo(panel.left(), panel.top() + 16);
        band.quadTo(panel.left(), panel.top(), panel.left() + 16, panel.top());
        band.lineTo(panel.right() - 16, panel.top());
        band.quadTo(panel.right(), panel.top(), panel.right(), panel.top() + 16);
        band.lineTo(panel.right(), panel.top() + kHeaderH);
        band.closeSubpath();
        p.fillPath(band, kHeader);

        p.setPen(QPen(kSeparator, 1));
        p.drawLine(QPointF(panel.left(), panel.top() + kHeaderH),
                   QPointF(panel.right(), panel.top() + kHeaderH));
        p.setClipping(false);

        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(kBorder, 1));
        p.drawRoundedRect(panel.adjusted(0.5, 0.5, -0.5, -0.5), 16, 16);
    }

    // The X shrinks the window into the tray; the tunnel keeps running and the
    // tray icon brings the panel back.
    void closeEvent(QCloseEvent* event) override {
        event->ignore();
        hide();
    }

private:
    QWidget* build_header() {
        auto* header = new QWidget;
        header->setFixedHeight(kHeaderH);
        header->setAttribute(Qt::WA_TranslucentBackground);

        auto* row = new QHBoxLayout(header);
        row->setContentsMargins(16, 14, 16, 14);
        row->setSpacing(12);
        row->addWidget(new AppLogo);

        auto* text = new QVBoxLayout;
        text->setSpacing(2);
        text->setContentsMargins(0, 0, 0, 0);
        title_ = new QLabel;
        title_->setFont(ui_font(16, true));
        title_->setTextFormat(Qt::RichText);
        subtitle_ = new QLabel("Virtual Network Interface");
        subtitle_->setFont(ui_font(12));
        subtitle_->setStyleSheet("color:#8B94A7;");
        text->addWidget(title_);
        text->addWidget(subtitle_);
        row->addLayout(text, 1);

        auto* close = new QPushButton("✕");
        close->setFixedSize(32, 32);
        close->setCursor(Qt::PointingHandCursor);
        close->setFont(ui_font(14, true));
        close->setStyleSheet(
            "QPushButton { background:transparent; color:#AAB3C5; border:none; border-radius:8px; }"
            "QPushButton:hover { background:rgba(239,68,68,0.15); color:#FCA5A5; }");
        QObject::connect(close, &QPushButton::clicked, [this] { hide(); });
        row->addWidget(close);
        return header;
    }

    QWidget* build_body() {
        auto* body = new QWidget;
        body->setAttribute(Qt::WA_TranslucentBackground);
        auto* root = new QVBoxLayout(body);
        root->setContentsMargins(16, 16, 16, 16);
        root->setSpacing(12);

        // Connection strip.
        auto* strip = new QFrame;
        strip->setObjectName("strip");
        strip->setStyleSheet(
            "QFrame#strip { background:#1A202C; border:1px solid #232936; border-radius:12px; }");
        auto* strip_row = new QHBoxLayout(strip);
        strip_row->setContentsMargins(12, 9, 12, 9);
        strip_row->setSpacing(8);

        dot_ = new PulseDot;
        strip_row->addWidget(dot_);

        // The peer count lives inside the status badge: no separate "Online"
        // label and no second line of text next to it.
        state_pill_ = new QLabel("— Peers connected");
        state_pill_->setFont(ui_font(12, true));
        state_pill_->setAlignment(Qt::AlignCenter);
        state_pill_->setStyleSheet(
            "background:rgba(34,197,94,0.20); color:#22C55E; border-radius:10px; padding:3px 9px;");
        strip_row->addWidget(state_pill_);
        strip_row->addStretch();

        tunnel_pill_ = new QLabel("Zone Network");
        tunnel_pill_->setFont(ui_font(11, true));
        tunnel_pill_->setAlignment(Qt::AlignCenter);
        // Gray until the first zone probe answers (panel_zone_status = 0).
        tunnel_pill_->setStyleSheet(
            "background:rgba(139,148,167,0.18); color:#8B94A7; border-radius:10px; padding:3px 9px;");
        strip_row->addWidget(tunnel_pill_);
        root->addWidget(strip);

        // 2x2 information cards.
        auto* grid = new QGridLayout;
        grid->setSpacing(12);
        grid->setContentsMargins(0, 0, 0, 0);

        auto* ip_card = new CardFrame;
        ip_card->setCursor(Qt::PointingHandCursor);
        ip_ = make_card("IP ADDRESS", Icon::Globe, "—", "Click to copy", false, ip_card);
        ip_card->on_click = [this] {
            const QString text = ip_.value->text();
            if (text.isEmpty() || text == "—") return;
            QApplication::clipboard()->setText(text);
            ip_.sub->setText("Copied ✓");
            ip_.sub->setStyleSheet("color:#6EE7B7;");
            QTimer::singleShot(1500, [this] {
                ip_.sub->setText("Click to copy");
                ip_.sub->setStyleSheet("color:#667085;");
            });
        };
        grid->addWidget(ip_.frame, 0, 0);

        uptime_ = make_card("UPTIME", Icon::Clock, "—", "● Live", false, nullptr);
        uptime_.sub->setStyleSheet("color:#6EE7B7;");
        grid->addWidget(uptime_.frame, 0, 1);

        ping_ = make_card("PING", Icon::Activity, "— ms", "last 48 s", false, nullptr);
        ping_.layout->addSpacing(2);
        spark_ = new Sparkline;
        ping_.layout->addWidget(spark_);
        grid->addWidget(ping_.frame, 1, 0);

        tunnel_ = make_card("NETWORK ACCESS", Icon::Shield, "Offline", "● No access", true, nullptr);
        grid->addWidget(tunnel_.frame, 1, 1);

        root->addLayout(grid);
        return body;
    }

    void sample_ping() {
        if (!connected_ || spark_ == nullptr) return;
        const int ms = panel_ping_ms.load();
        spark_->push(ms >= 0 ? ms : -1);  // real RTT, or a gap when nothing replied
    }

    void refresh() {
        const long long since = panel_connected_since.load();
        connected_ = since > 0;

        title_->setText(QString("RootLayer <span style=\"color:%1\">• %2</span>")
                            .arg(connected_ ? "#22C55E" : "#8B94A7",
                                 connected_ ? "Online" : "Offline"));

        const QString ip = connected_ ? QString::fromStdString(virtual_ip) : QString("—");
        ip_.value->setText(ip.isEmpty() ? QString("—") : ip);

        if (connected_) {
            const long long now = static_cast<long long>(QDateTime::currentSecsSinceEpoch());
            uptime_.value->setText(format_uptime(now - since));
            uptime_.sub->setText("● Live");
            uptime_.sub->setStyleSheet("color:#6EE7B7;");
        } else {
            uptime_.value->setText("—");
            uptime_.sub->setText("Not connected");
            uptime_.sub->setStyleSheet("color:#667085;");
        }

        const int ms = panel_ping_ms.load();
        if (connected_ && ms >= 0) {
            ping_.value->setText(QString("%1 ms").arg(ms));
            ping_.value->setStyleSheet("color:#EEF2F7;");
            ping_.sub->setText("last 48 s");
            ping_.sub->setStyleSheet("color:#667085;");
        } else {
            ping_.value->setText("— ms");
            ping_.value->setStyleSheet("color:#667085;");
            const std::string target = panel_ping_target_value();
            ping_.sub->setText(connected_ && !target.empty()
                                   ? QString("no reply from %1").arg(QString::fromStdString(target))
                                   : (connected_ ? "no reply" : "not connected"));
            ping_.sub->setStyleSheet("color:#667085;");
        }

        const bool tunneling = connected_ && !gateway_ip.empty();
        tunnel_.value->setText(connected_ ? "Online" : "Offline");
        tunnel_.value->setStyleSheet(connected_ ? "color:#22C55E;" : "color:#8B94A7;");
        tunnel_.sub->setText(tunneling ? "● Access granted"
                                       : (connected_ ? "● No gateway" : "● No access"));
        tunnel_.sub->setStyleSheet(tunneling ? "color:#6EE7B7;"
                                            : (connected_ ? "color:#E9C46A;" : "color:#667085;"));

        dot_->setActive(connected_);
        const int peers = peer_count.load();
        if (!connected_) {
            state_pill_->setText("Offline");
        } else if (peers > 0) {
            state_pill_->setText(peers == 1 ? QString("1 Peer connected")
                                            : QString("%1 Peers connected").arg(peers));
        } else {
            state_pill_->setText("No peers yet");
        }
        state_pill_->setStyleSheet(connected_
            ? "background:rgba(34,197,94,0.20); color:#22C55E; border-radius:10px; padding:3px 9px;"
            : "background:rgba(139,148,167,0.18); color:#8B94A7; border-radius:10px; padding:3px 9px;");
        // Fixed badge text: the pill colour reports the root server's domain
        // zone system - green when it answers, red when it does not, gray
        // while the first probe is still running.
        tunnel_pill_->setText("Zone Network");
        const int zone = panel_zone_status.load();
        if (zone == 1) {
            tunnel_pill_->setStyleSheet(
                "background:rgba(34,197,94,0.15); color:#6EE7B7; border-radius:10px; padding:3px 9px;");
        } else if (zone == 2) {
            tunnel_pill_->setStyleSheet(
                "background:rgba(239,68,68,0.15); color:#FCA5A5; border-radius:10px; padding:3px 9px;");
        } else {
            tunnel_pill_->setStyleSheet(
                "background:rgba(139,148,167,0.18); color:#8B94A7; border-radius:10px; padding:3px 9px;");
        }

        if (!connected_) {
            spark_->reset();
        }
    }

    QLabel* title_ = nullptr;
    QLabel* subtitle_ = nullptr;
    QLabel* state_pill_ = nullptr;
    QLabel* tunnel_pill_ = nullptr;
    PulseDot* dot_ = nullptr;
    // (the peer count is shown inside state_pill_, so there is no separate label)
    Sparkline* spark_ = nullptr;
    Card ip_;
    Card uptime_;
    Card ping_;
    Card tunnel_;
    bool connected_ = false;
};

// Makes the whole panel draggable, including over labels and cards: a press on
// any child starts a window move, and the event keeps bubbling so buttons and
// the copy-on-click card still behave normally.
class DragBridge : public QObject {
public:
    explicit DragBridge(QWidget* panel, QObject* parent = nullptr)
        : QObject(parent), panel_(panel) {}

    bool eventFilter(QObject* watched, QEvent* event) override {
        auto* widget = qobject_cast<QWidget*>(watched);
        if (widget == nullptr || widget->window() != panel_) return false;
        if (qobject_cast<QPushButton*>(widget) != nullptr) return false;

        switch (event->type()) {
            case QEvent::MouseButtonPress: {
                auto* mouse = static_cast<QMouseEvent*>(event);
                if (mouse->button() == Qt::LeftButton) {
                    dragging_ = true;
                    offset_ = mouse->globalPosition().toPoint() - panel_->frameGeometry().topLeft();
                }
                break;
            }
            case QEvent::MouseMove: {
                auto* mouse = static_cast<QMouseEvent*>(event);
                if (dragging_ && (mouse->buttons() & Qt::LeftButton)) {
                    panel_->move(mouse->globalPosition().toPoint() - offset_);
                }
                break;
            }
            case QEvent::MouseButtonRelease:
                dragging_ = false;
                break;
            default:
                break;
        }
        return false;  // let the child handle its own click as well
    }

private:
    QWidget* panel_;
    bool dragging_ = false;
    QPoint offset_;
};

}  // namespace

int run_qt_ui() {
    static int argc = 1;
    static char name[] = "client";
    static char* argv[] = {name, nullptr, nullptr};
    QApplication app(argc, argv);
    app.setApplicationName("RootLayer");
    app.setQuitOnLastWindowClosed(false);
    // Window/taskbar icon comes from the same resources folder as the rest.
    for (const char* name : {"exe_client.ico", "exe_client.png"}) {
        const QString path = icon_path(name);
        if (path.isEmpty()) continue;
        QIcon icon(path);
        if (!icon.isNull()) {
            app.setWindowIcon(icon);
            break;
        }
    }

    ClientPanel panel;

    auto* drag = new DragBridge(&panel, &app);
    app.installEventFilter(drag);

    QMenu menu;
    QAction* show_action = menu.addAction("Show window");
    QAction* exit_action = menu.addAction("Exit");
    QObject::connect(show_action, &QAction::triggered, [&panel] {
        panel.show();
        panel.raise();
        panel.activateWindow();
    });
    QObject::connect(exit_action, &QAction::triggered, [&app] {
        tray_request_exit();
        QCoreApplication::quit();
    });

    QSystemTrayIcon tray(tray_icon(false));
    tray.setContextMenu(&menu);
    tray.setToolTip("RootLayer");
    QObject::connect(&tray, &QSystemTrayIcon::activated,
                     [&panel](QSystemTrayIcon::ActivationReason reason) {
                         if (reason == QSystemTrayIcon::Trigger) {
                             if (panel.isVisible()) {
                                 panel.hide();
                             } else {
                                 panel.show();
                                 panel.raise();
                             }
                         }
                     });
    tray.show();

    // The tray icon follows the tunnel state, exactly like the panel.
    auto* icon_timer = new QTimer(&app);
    icon_timer->setInterval(1000);
    bool last_state = false;
    QObject::connect(icon_timer, &QTimer::timeout, [&tray, &last_state, &panel] {
        const bool connected = panel.connected();
        if (connected != last_state) {
            last_state = connected;
            tray.setIcon(tray_icon(connected));
            tray.setToolTip(connected ? "RootLayer - Online" : "RootLayer - Offline");
        }
    });
    icon_timer->start();

    const QRect screen = QGuiApplication::primaryScreen()->availableGeometry();
    panel.move(screen.right() - panel.width() - 24, screen.bottom() - panel.height() - 24);
    panel.show();

    return app.exec();
}

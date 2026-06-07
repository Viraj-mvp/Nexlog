import QtQuick 2.15

Rectangle {
    id: root
    property var bridge
    property var lastAnalysis: ({})
    property string accent: "#62f3ff"

    height: bridge && bridge.busy ? 78 : 0
    visible: bridge ? bridge.busy : false
    radius: 24
    color: bridge && bridge.busy ? "#142451" : "#0f1732"
    border.color: bridge && bridge.busy ? accent : "#26375f"
    clip: true

    Canvas {
        id: scan
        anchors.fill: parent
        opacity: bridge && bridge.busy ? 0.82 : 0.18
        property real sweep: 0
        onPaint: {
            var ctx = getContext("2d")
            ctx.reset()
            var g = ctx.createLinearGradient(0, 0, width, 0)
            g.addColorStop(0, "rgba(98,243,255,0)")
            g.addColorStop(Math.max(0, sweep - 0.08), "rgba(98,243,255,0.02)")
            g.addColorStop(sweep, "rgba(98,243,255,0.30)")
            g.addColorStop(Math.min(1, sweep + 0.08), "rgba(255,183,77,0.11)")
            g.addColorStop(1, "rgba(98,243,255,0)")
            ctx.fillStyle = g
            ctx.fillRect(0, 0, width, height)
            ctx.strokeStyle = "rgba(98,243,255,0.06)"
            for (var x = 0; x < width; x += 24) {
                ctx.beginPath()
                ctx.moveTo(x, 0)
                ctx.lineTo(x + 24, height)
                ctx.stroke()
            }
        }
        Timer {
            interval: 32
            running: root.visible && (root.bridge ? (root.bridge.busy && !root.bridge.reducedMotion) : false)
            repeat: true
            onTriggered: {
                scan.sweep = (scan.sweep + 0.016) % 1
                scan.requestPaint()
            }
        }
        Component.onCompleted: requestPaint()
    }

    Text {
        text: bridge && bridge.busy ? "ANALYSING EVIDENCE" : (lastAnalysis.state === "complete" ? "LAST ANALYSIS COMPLETE" : (lastAnalysis.state === "error" ? "ANALYSIS ERROR" : "READY"))
        color: bridge && bridge.busy ? accent : "#8fa0c6"
        font.pixelSize: 11
        font.letterSpacing: 2.0
        font.weight: Font.Bold
        anchors.left: parent.left
        anchors.leftMargin: 20
        anchors.top: parent.top
        anchors.topMargin: 12
    }

    Text {
        text: bridge ? bridge.statusText : "Ready"
        color: "#f4f8ff"
        font.pixelSize: 16
        font.weight: Font.Bold
        anchors.left: parent.left
        anchors.leftMargin: 20
        anchors.right: progressText.left
        anchors.rightMargin: 16
        anchors.top: parent.top
        anchors.topMargin: 32
        elide: Text.ElideMiddle
    }

    Text {
        id: progressText
        text: (bridge ? bridge.progressValue : 0) + "%"
        color: accent
        font.pixelSize: 22
        font.weight: Font.Black
        anchors.right: parent.right
        anchors.rightMargin: 22
        anchors.verticalCenter: parent.verticalCenter
    }

    Rectangle {
        height: 5
        radius: 3
        color: "#20305a"
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: 20
        anchors.rightMargin: 78
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 12
        Rectangle {
            height: parent.height
            width: parent.width * ((bridge ? bridge.progressValue : 0) / 100)
            radius: parent.radius
            color: bridge && bridge.busy ? accent : "#7df9c7"
            Behavior on width { NumberAnimation { duration: 220; easing.type: Easing.OutCubic } }
        }
    }
}

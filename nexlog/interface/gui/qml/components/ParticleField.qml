import QtQuick 2.15

Canvas {
    id: canvas
    property color amber: "#ffb347"
    property color teal: "#23d7c8"
    property bool reducedMotion: false
    property bool active: true
    property real phase: 0

    onPaint: {
        var ctx = getContext("2d")
        ctx.reset()
        ctx.clearRect(0, 0, width, height)

        var grid = 44
        ctx.lineWidth = 1
        for (var x = -grid; x < width + grid; x += grid) {
            var alpha = 0.035 + 0.035 * Math.sin((x * 0.015) + phase)
            ctx.strokeStyle = "rgba(255,179,71," + alpha + ")"
            ctx.beginPath()
            ctx.moveTo(x, 0)
            ctx.lineTo(x + 120, height)
            ctx.stroke()
        }

        var count = canvas.active ? 54 : 14
        for (var i = 0; i < count; i++) {
            var px = (i * 97 + phase * 30) % Math.max(width, 1)
            var py = (i * 53 + Math.sin(phase + i) * 24 + height) % Math.max(height, 1)
            var size = 1.5 + (i % 4)
            var isAmber = i % 3 !== 0
            ctx.fillStyle = isAmber ? "rgba(255,179,71,0.34)" : "rgba(35,215,200,0.24)"
            ctx.fillRect(px, py, size, size)
        }
    }

    Timer {
        interval: 32
        running: canvas.visible && canvas.active && !canvas.reducedMotion
        repeat: true
        onTriggered: {
            canvas.phase += 0.018
            canvas.requestPaint()
        }
    }

    Component.onCompleted: requestPaint()
}

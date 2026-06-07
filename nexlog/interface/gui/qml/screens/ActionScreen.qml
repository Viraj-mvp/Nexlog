import QtQuick 2.15

Item {
    id: root
    property var bridge
    property string title: "NexLog"
    property string subtitle: ""
    property string mode: "findings"
    property var rows: []
    property var graph: ({ nodes: [], edges: [] })
    property var tools: ({})
    property var lastAnalysis: bridge ? bridge.lastAnalysisSummary : ({})

    function refresh() {
        if (!bridge) return
        if (mode === "findings") rows = bridge.findingsSnapshot()
        else if (mode === "timeline") rows = bridge.timelineSnapshot()
        else if (mode === "mitre") rows = bridge.mitreSnapshot()
        else if (mode === "graph") graph = bridge.graphSnapshot()
        else if (mode === "tools" || mode === "ai") tools = bridge.toolsSnapshot()
    }

    function sevColor(sev) {
        if (sev === "CRITICAL") return "#ff4d7d"
        if (sev === "HIGH") return "#ff9f43"
        if (sev === "MEDIUM") return "#ffd166"
        if (sev === "LOW") return "#5ee7ff"
        return "#93a4c7"
    }

    Component.onCompleted: refresh()

    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onFindingsChanged(data) { if (mode === "findings") rows = data }
        function onTimelineChanged(data) { if (mode === "timeline") rows = data }
        function onMitreChanged(data) { if (mode === "mitre") rows = data }
        function onGraphChanged(data) { if (mode === "graph") graph = data }
        function onToolsChanged(data) { if (mode === "tools" || mode === "ai") tools = data }
        function onLastAnalysisChanged() { lastAnalysis = bridge.lastAnalysisSummary }
        function onAnalysisComplete(summary) {
            lastAnalysis = summary
            refresh()
        }
    }

    Rectangle {
        anchors.fill: parent
        color: "#090d1b"
    }

    Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: Math.max(height + 1, 860)
        clip: true

        Item {
            width: parent.width
            height: 860

            Rectangle {
                id: hero
                x: 28
                y: 26
                width: parent.width - 56
                height: 132
                radius: 28
                color: "#101735"
                border.color: "#3158a8"

                Text {
                    text: title
                    color: "#f4f8ff"
                    font.pixelSize: 31
                    font.weight: Font.Black
                    x: 24
                    y: 22
                }

                Text {
                    text: subtitle
                    color: "#aab9dd"
                    font.pixelSize: 14
                    width: parent.width * 0.56
                    wrapMode: Text.WordWrap
                    x: 24
                    y: 67
                }

                Row {
                    anchors.right: parent.right
                    anchors.rightMargin: 22
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 10
                    ActionButton { label: "Analyse"; primary: true; onClicked: bridge.analyseLog() }
                    ActionButton { label: "Open Log"; accent: "#8a5cff"; onClicked: bridge.openLogDialog() }
                    ActionButton { label: "Refresh"; accent: "#93a4c7"; onClicked: { bridge.refreshSessions(); root.refresh() } }
                }
            }

            Loader {
                x: 28
                y: 180
                width: parent.width - 56
                height: 620
                sourceComponent: {
                    if (mode === "graph") return graphComponent
                    if (mode === "tools") return toolsComponent
                    if (mode === "ai") return aiComponent
                    return listComponent
                }
            }
        }
    }

    Component {
        id: listComponent
        Rectangle {
            radius: 28
            color: "#11162b"
            border.color: "#24345f"

            Row {
                id: listActions
                x: 20
                y: 18
                spacing: 10
                visible: mode === "findings" || mode === "timeline" || mode === "mitre"
                ActionButton { label: "PDF"; onClicked: bridge.exportReport("pdf") }
                ActionButton { label: "JSON"; accent: "#8a5cff"; visible: mode === "findings"; onClicked: bridge.exportReport("json") }
                ActionButton { label: "STIX"; accent: "#7df9c7"; visible: mode === "findings"; onClicked: bridge.exportStix() }
                ActionButton { label: "IOC CSV"; accent: "#ffd166"; visible: mode === "findings"; onClicked: bridge.exportIocs("csv") }
                ActionButton { label: "Refresh"; accent: "#93a4c7"; onClicked: { bridge.refreshSessions(); root.refresh() } }
            }

            Repeater {
                model: rows
                delegate: Rectangle {
                    required property var modelData
                    required property int index
                    x: 20
                    y: 74 + index * 58
                    width: parent.width - 40
                    height: mode === "findings" ? 68 : 56
                    radius: 16
                    color: index % 2 === 0 ? "#151d38" : "#101735"
                    border.color: "#213361"
                    visible: index < 8

                    Rectangle {
                        width: 7
                        height: 30
                        radius: 4
                        color: sevColor(modelData.severity || "INFO")
                        anchors.left: parent.left
                        anchors.leftMargin: 12
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                        text: mode === "mitre"
                              ? ((modelData.technique || "-") + "  " + (modelData.count || 0))
                              : ((modelData.severity || "INFO") + "  " + (modelData.rule_name || modelData.rule_id || "event"))
                        color: "#eaf3ff"
                        font.pixelSize: 14
                        font.weight: Font.DemiBold
                        anchors.left: parent.left
                        anchors.leftMargin: 28
                        anchors.right: stateRow.left
                        anchors.rightMargin: 16
                        anchors.top: parent.top
                        anchors.topMargin: 8
                        elide: Text.ElideRight
                    }

                    Text {
                        text: mode === "timeline"
                              ? ((modelData.timestamp || "").slice(0, 19) + "  " + (modelData.source_ip || modelData.hostname || "unknown"))
                              : (mode === "mitre"
                                 ? "Technique coverage from the current case"
                                 : ((modelData.category || "") + "  risk " + (modelData.risk_score || "0") + "  src " + (modelData.source_ip || modelData.hostname || "unknown")))
                        color: "#8fa0c6"
                        font.pixelSize: 12
                        anchors.left: parent.left
                        anchors.leftMargin: 28
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 7
                        width: parent.width - 240
                        elide: Text.ElideRight
                    }

                    Text {
                        visible: mode === "findings"
                        text: modelData.trigger_line || "No trigger preview stored for this finding."
                        color: "#65779d"
                        font.pixelSize: 11
                        anchors.left: parent.left
                        anchors.leftMargin: 28
                        anchors.right: stateRow.left
                        anchors.rightMargin: 16
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 6
                        elide: Text.ElideRight
                    }

                    Row {
                        id: stateRow
                        spacing: 6
                        visible: mode === "findings"
                        anchors.right: parent.right
                        anchors.rightMargin: 10
                        anchors.verticalCenter: parent.verticalCenter
                        ActionButton { width: 48; height: 27; label: "ACK"; accent: "#5ee7ff"; onClicked: bridge.setFindingState(modelData.finding_id, "ACK") }
                        ActionButton { width: 48; height: 27; label: "ESC"; accent: "#ff9f43"; onClicked: bridge.setFindingState(modelData.finding_id, "ESCALATE") }
                        ActionButton { width: 42; height: 27; label: "FP"; accent: "#93a4c7"; onClicked: bridge.setFindingState(modelData.finding_id, "FP") }
                    }
                }
            }

            Text {
                visible: !(rows && rows.length)
                text: lastAnalysis.state === "complete"
                      ? "Analysis completed, but this view has no matching records. Try lowering severity or analysing a richer log."
                      : "No data yet. Click Analyse, choose a log, then this panel will populate with backend detection results."
                color: "#8fa0c6"
                font.pixelSize: 16
                width: parent.width - 120
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.centerIn: parent
            }
        }
    }

    Component {
        id: graphComponent
        Rectangle {
            radius: 28
            color: "#0d1328"
            border.color: "#24345f"
            property var nodes: graph.nodes || []
            property var edges: graph.edges || []

            Canvas {
                id: graphCanvas
                anchors.fill: parent
                anchors.margins: 20
                property real phase: 0
                onPaint: {
                    var ctx = getContext("2d")
                    ctx.reset()
                    var count = Math.max(1, nodes.length)
                    var positions = {}
                    ctx.strokeStyle = "rgba(94,231,255,0.08)"
                    for (var gx = 0; gx < width; gx += 42) {
                        ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, height); ctx.stroke()
                    }
                    for (var gy = 0; gy < height; gy += 42) {
                        ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(width, gy); ctx.stroke()
                    }
                    for (var i = 0; i < count; i++) {
                        var angle = (Math.PI * 2 * i / count) + phase
                        var radius = Math.min(width, height) * (0.27 + (i % 3) * 0.05)
                        positions[nodes[i].id] = {
                            x: width / 2 + Math.cos(angle) * radius,
                            y: height / 2 + Math.sin(angle) * radius
                        }
                    }
                    ctx.lineWidth = 1.3
                    for (var e = 0; e < Math.min(edges.length, 180); e++) {
                        var a = positions[edges[e].from]
                        var b = positions[edges[e].to]
                        if (!a || !b) continue
                        ctx.strokeStyle = "rgba(138,92,255,0.35)"
                        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
                    }
                    for (var n = 0; n < count; n++) {
                        var p = positions[nodes[n].id]
                        var r = 9 + Math.min(10, nodes[n].weight || 1)
                        ctx.fillStyle = sevColor(nodes[n].severity || "INFO")
                        ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI * 2); ctx.fill()
                        ctx.fillStyle = "#eaf3ff"
                        ctx.font = "12px sans-serif"
                        ctx.fillText((nodes[n].label || "").slice(0, 22), p.x + r + 6, p.y + 4)
                    }
                }
                Timer {
                    interval: 80
                    running: bridge ? (!bridge.reducedMotion && nodes.length > 0) : false
                    repeat: true
                    onTriggered: { graphCanvas.phase += 0.003; graphCanvas.requestPaint() }
                }
                Component.onCompleted: requestPaint()
            }

            Row {
                x: 20
                y: 18
                spacing: 10
                ActionButton { label: "Fit"; onClicked: graphCanvas.requestPaint() }
                ActionButton { label: "PDF"; accent: "#8a5cff"; onClicked: bridge.exportReport("pdf") }
                ActionButton { label: "Refresh"; accent: "#93a4c7"; onClicked: bridge.refreshSessions() }
            }

            Text {
                visible: !(graph.nodes && graph.nodes.length)
                text: "No graph yet. Analyse a log to build source-category-rule relationships."
                color: "#8fa0c6"
                font.pixelSize: 16
                anchors.centerIn: parent
            }
        }
    }

    Component {
        id: toolsComponent
        Rectangle {
            radius: 28
            color: "#11162b"
            border.color: "#24345f"

            Grid {
                x: 22
                y: 22
                columns: 4
                spacing: 12
                ActionButton { width: 150; label: "PDF Report"; onClicked: bridge.exportReport("pdf") }
                ActionButton { width: 150; label: "Markdown"; accent: "#8a5cff"; onClicked: bridge.exportReport("markdown") }
                ActionButton { width: 150; label: "Text"; accent: "#8a5cff"; onClicked: bridge.exportReport("text") }
                ActionButton { width: 150; label: "JSON"; accent: "#8a5cff"; onClicked: bridge.exportReport("json") }
                ActionButton { width: 150; label: "STIX"; accent: "#7df9c7"; onClicked: bridge.exportStix() }
                ActionButton { width: 150; label: "IOC CSV"; accent: "#ffd166"; onClicked: bridge.exportIocs("csv") }
                ActionButton { width: 150; label: "IOC Bundle"; accent: "#ffd166"; onClicked: bridge.exportIocs("all") }
                ActionButton { width: 150; label: "Sigma"; accent: "#5ee7ff"; onClicked: bridge.exportSigma() }
                ActionButton { width: 150; label: "UEBA"; accent: "#ff9f43"; onClicked: bridge.runUeba() }
                ActionButton { width: 150; label: "AI Report"; accent: "#8a5cff"; onClicked: bridge.generateAiReport() }
                ActionButton { width: 150; label: "Canary Token"; accent: "#ff4d7d"; onClicked: bridge.createCanaryToken() }
                ActionButton { width: 150; label: "Canary Listen"; accent: "#ff4d7d"; onClicked: bridge.startCanaryListener() }
            }

            Rectangle {
                x: 22
                y: 190
                width: parent.width - 44
                height: parent.height - 212
                radius: 22
                color: "#0d1328"
                border.color: "#213361"
                Text {
                    text: (tools.lastAction || "Ready") + "\n\n" + (tools.lastOutput || tools.message || tools.preview || "Choose a tool action above.")
                    color: "#dce8ff"
                    font.pixelSize: 14
                    wrapMode: Text.WordWrap
                    anchors.fill: parent
                    anchors.margins: 22
                }
            }
        }
    }

    Component {
        id: aiComponent
        Rectangle {
            radius: 28
            color: "#11162b"
            border.color: "#24345f"

            Text {
                text: "Offline-first AI query is kept lazy. Use Index Session when you are ready to opt into AI features."
                color: "#aab9dd"
                font.pixelSize: 16
                wrapMode: Text.WordWrap
                x: 24
                y: 24
                width: parent.width - 48
            }

            Row {
                x: 24
                y: 86
                spacing: 12
                ActionButton { label: "Index Session"; width: 150; onClicked: bridge.indexSession() }
                ActionButton { label: "Clear"; accent: "#93a4c7"; onClicked: bridge.clearAiHistory() }
                ActionButton { label: "AI Report"; accent: "#8a5cff"; onClicked: bridge.generateAiReport() }
            }

            Rectangle {
                x: 24
                y: 150
                width: parent.width - 48
                height: parent.height - 174
                radius: 22
                color: "#0d1328"
                border.color: "#213361"
                Text {
                    text: tools.preview || tools.message || tools.lastOutput || "Suggested prompts: Summarize this case, show critical attack path, list top IOCs, explain MITRE coverage."
                    color: "#dce8ff"
                    font.pixelSize: 14
                    wrapMode: Text.WordWrap
                    anchors.fill: parent
                    anchors.margins: 22
                }
            }
        }
    }

    component ActionButton: Rectangle {
        id: btn
        property string label: "Action"
        property string accent: "#5ee7ff"
        property bool primary: false
        signal clicked()
        width: 108
        height: 38
        radius: 14
        color: primary ? accent : (mouse.containsMouse ? "#1b2854" : "#121b3a")
        border.color: accent
        border.width: primary ? 0 : 1
        scale: mouse.containsMouse ? 1.035 : 1
        Behavior on scale { NumberAnimation { duration: 120; easing.type: Easing.OutCubic } }
        Text {
            anchors.centerIn: parent
            text: label
            color: primary ? "#08101f" : "#dce8ff"
            font.pixelSize: 12
            font.weight: Font.Bold
        }
        MouseArea {
            id: mouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: btn.clicked()
        }
    }
}

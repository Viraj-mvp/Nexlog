import QtQuick 2.15
import "../components" as C

Item {
    id: root
    property var bridge
    property string globalQuery: ""
    property var tools: ({})
    property var perf: ({})
    property bool drawerVisible: false
    property real drawerX: Math.max(24, width - 456)
    property real drawerY: 148

    function refresh() {
        if (bridge) {
            tools = bridge.toolsSnapshot()
            perf = bridge.resourceSnapshot()
        }
    }
    function openDrawer() {
        if (tools && ((tools.lastAction || "") !== "Ready" || tools.running)) {
            drawerVisible = true
        }
    }
    function accentFor(kind) {
        if (tools.error) return "#ff4d7d"
        if (kind === "pdf" || kind === "markdown" || kind === "text" || kind === "json") return "#62f3ff"
        if (kind === "stix" || kind === "ioc") return "#7df9c7"
        if (kind === "ai-report") return "#a88cff"
        if (kind === "graph") return "#ffb74d"
        return "#ffd166"
    }

    Component.onCompleted: refresh()
    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onToolsChanged(data) {
            tools = data
            root.openDrawer()
        }
        function onPerformanceChanged() {
            if (bridge) perf = bridge.resourceSnapshot()
        }
    }

    Rectangle { anchors.fill: parent; color: "#080d1e" }

    Flickable {
        id: scroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: toolsColumn.implicitHeight + 56
        clip: true

        Column {
            id: toolsColumn
            width: scroll.width
            spacing: 14
            padding: 24

            C.BentoCard {
                width: parent.width - 48
                height: 152
                title: "Tools Console"
                subtitle: "Reports, STIX, IOC bundles, Sigma, UEBA, AI report, Canary controls, and case bundle export."
                accent: "#ffb74d"
                Flow {
                    anchors.fill: parent
                    spacing: 10
                    C.NeonButton { label: "Refresh"; accent: "#ffb74d"; onClicked: { bridge.refreshSessions(); root.refresh() } }
                    C.NeonButton { label: "Open Case"; accent: "#7df9c7"; onClicked: bridge.openCaseDialog() }
                    C.NeonButton { label: "New Case"; accent: "#7df9c7"; onClicked: bridge.newCaseDialog() }
                    C.NeonButton { label: "Show Result"; accent: "#a88cff"; enabled: (tools.lastAction || "") !== "Ready"; onClicked: root.drawerVisible = true }
                }
            }

            Flow {
                id: toolsFlow
                width: parent.width - 48
                height: childrenRect.height
                spacing: 14

                ToolCard { title: "PDF Report"; detail: "Case-ready executive and technical report."; accent: "#62f3ff"; actionLabel: "Export PDF"; onRun: bridge.exportReport("pdf") }
                ToolCard { title: "Markdown / JSON / Text"; detail: "Portable report formats for GitHub, notes, or pipelines."; accent: "#a88cff"; actionLabel: "Export MD"; onRun: bridge.exportReport("markdown") }
                ToolCard { title: "STIX 2.1"; detail: "Threat intelligence bundle for sharing indicators and findings."; accent: "#7df9c7"; actionLabel: "Export STIX"; onRun: bridge.exportStix() }
                ToolCard { title: "IOC Bundle"; detail: "CSV or complete IOC export from extracted indicators."; accent: "#ffd166"; actionLabel: "IOC CSV"; onRun: bridge.exportIocs("csv") }
                ToolCard { title: "Sigma"; detail: "Export detection rules from case findings."; accent: "#ff9f43"; actionLabel: "Export Sigma"; onRun: bridge.exportSigma() }
                ToolCard { title: "UEBA"; detail: "Run local anomaly scoring over the active session."; accent: "#ff4d7d"; actionLabel: "Run UEBA"; onRun: bridge.runUeba() }
                ToolCard { title: "AI Report"; detail: "Generate offline-safe case explanation preview."; accent: "#a88cff"; actionLabel: "AI Report"; onRun: bridge.generateAiReport() }
                ToolCard { title: "Case Bundle"; detail: "Archive DB and exports for handoff."; accent: "#62f3ff"; actionLabel: "Bundle"; onRun: bridge.exportCaseBundle() }
                ToolCard { title: "Canary"; detail: "Create or monitor canary token workflows."; accent: "#7df9c7"; actionLabel: "Create"; onRun: bridge.createCanaryToken() }
                ToolCard { title: "Graph Export"; detail: "Export attack graph as PNG or GraphML from the graph screen."; accent: "#ffb74d"; actionLabel: "GraphML"; onRun: bridge.exportGraph("graphml") }
                ToolCard {
                    title: "Performance Mode"
                    detail: "Mode: " + (perf.hardwareMode || "adaptive") +
                            "\nWorkers: " + (perf.maxWorkers || "?") +
                            "\nBatch: " + (perf.batchSize || "?") +
                            "\nCPU: " + (perf.cpuPercent !== undefined ? Math.round(perf.cpuPercent) + "%" : "n/a") +
                            "\nMemory: " + (perf.memoryPercent !== undefined ? Math.round(perf.memoryPercent) + "%" : "n/a")
                    accent: "#62f3ff"
                    actionLabel: "Cycle Mode"
                    onRun: {
                        var current = perf.hardwareMode || "adaptive"
                        bridge.setHardwareMode(current === "adaptive" ? "performance" : (current === "performance" ? "conservative" : "adaptive"))
                        root.refresh()
                    }
                }
            }
        }
    }

    Rectangle {
        id: resultDrawer
        visible: root.drawerVisible
        z: 8
        x: Math.max(18, Math.min(root.drawerX, root.width - width - 18))
        y: Math.max(18, Math.min(root.drawerY, root.height - height - 18))
        width: Math.min(420, root.width - 36)
        height: Math.min(360, root.height - 36)
        radius: 28
        color: "#ee101735"
        border.color: root.accentFor(tools.resultKind || "")
        border.width: 1
        clip: true

        Rectangle {
            id: handle
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: 54
            color: "#17234a"
            opacity: 0.96

            Text {
                text: tools.running ? "WORKING" : (tools.error ? "ACTION FAILED" : "ACTION RESULT")
                color: root.accentFor(tools.resultKind || "")
                font.pixelSize: 11
                font.letterSpacing: 1.7
                font.weight: Font.Bold
                x: 18
                y: 9
            }
            Text {
                text: tools.lastAction || "Ready"
                color: "#f4f8ff"
                font.pixelSize: 16
                font.weight: Font.Black
                x: 18
                y: 27
                width: parent.width - 78
                elide: Text.ElideRight
            }
            C.NeonButton {
                width: 38
                height: 30
                compact: true
                label: "X"
                accent: "#93a4c7"
                anchors.right: parent.right
                anchors.rightMargin: 12
                anchors.verticalCenter: parent.verticalCenter
                onClicked: root.drawerVisible = false
            }
            MouseArea {
                anchors.fill: parent
                anchors.rightMargin: 58
                cursorShape: Qt.SizeAllCursor
                property real dx: 0
                property real dy: 0
                onPressed: function(mouse) {
                    dx = mouse.x
                    dy = mouse.y
                }
                onPositionChanged: function(mouse) {
                    root.drawerX = resultDrawer.x + mouse.x - dx
                    root.drawerY = resultDrawer.y + mouse.y - dy
                }
            }
        }

        Rectangle {
            visible: tools.running
            height: 3
            width: 96
            radius: 2
            color: root.accentFor(tools.resultKind || "")
            y: handle.height
            x: -110
            SequentialAnimation on x {
                running: resultDrawer.visible && tools.running && (!bridge || !bridge.reducedMotion)
                loops: Animation.Infinite
                NumberAnimation { from: -110; to: resultDrawer.width + 20; duration: 980; easing.type: Easing.InOutQuad }
            }
        }

        Flickable {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: handle.bottom
            anchors.bottom: actions.top
            anchors.margins: 18
            contentWidth: width
            contentHeight: drawerText.height + 20
            clip: true

            Text {
                id: drawerText
                width: parent.width
                text: (tools.preview || tools.lastOutput || "No output yet.") +
                      ((tools.resultPath || "") ? ("\n\nFile: " + tools.resultPath) : "") +
                      ((tools.count || 0) ? ("\nCount: " + tools.count) : "")
                color: "#dce8ff"
                font.pixelSize: 13
                lineHeight: 1.18
                wrapMode: Text.WordWrap
            }
        }

        Flow {
            id: actions
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.margins: 18
            height: childrenRect.height
            spacing: 8
            C.NeonButton {
                label: "Open Folder"
                accent: "#7df9c7"
                enabled: !!tools.resultPath
                onClicked: bridge.openResultFolder(tools.resultPath)
            }
            C.NeonButton {
                label: "Copy Path"
                accent: "#62f3ff"
                enabled: !!tools.resultPath
                onClicked: bridge.copyText(tools.resultPath)
            }
            C.NeonButton {
                label: "Close"
                accent: "#93a4c7"
                onClicked: root.drawerVisible = false
            }
        }
    }

    component ToolCard: C.BentoCard {
        id: toolCard
        property string detail: ""
        property string actionLabel: "Run"
        signal run()
        width: 236
        height: 220
        subtitle: detail

        C.NeonButton {
            anchors.left: parent.left
            anchors.bottom: parent.bottom
            label: actionLabel
            accent: toolCard.accent
            primary: true
            onClicked: run()
        }
    }
}

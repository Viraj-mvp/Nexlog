import QtQuick 2.15
import "../components" as C

Item {
    id: root
    property var bridge
    property string globalQuery: ""
    property var snapshot: ({})
    property var lastAnalysis: bridge ? bridge.lastAnalysisSummary : ({})
    property var severityChoices: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    property var selectedEvidence: snapshot.selectedEvidence || []
    property var analysisQueue: snapshot.analysisQueue || ({})
    property var historyGroups: snapshot.historyGroups || []
    signal navigate(string screen)

    function refresh() {
        if (bridge) snapshot = bridge.dashboardSnapshot()
    }

    function sevColor(sev) {
        if (sev === "CRITICAL") return "#ff4d7d"
        if (sev === "HIGH") return "#ff9f43"
        if (sev === "MEDIUM") return "#ffd166"
        if (sev === "LOW") return "#62f3ff"
        return "#93a4c7"
    }

    function columnCount() {
        if (width >= 1240) return 3
        if (width >= 860) return 2
        return 1
    }

    function cardWidth(span) {
        var cols = columnCount()
        var gap = 16
        var inner = Math.max(320, width - 56)
        var actualSpan = Math.min(span, cols)
        return Math.floor((inner - gap * (cols - 1)) / cols * actualSpan + gap * (actualSpan - 1))
    }

    function severityModel() {
        return [
            { name: "CRITICAL", count: snapshot.critical || 0 },
            { name: "HIGH", count: snapshot.high || 0 },
            { name: "MEDIUM", count: snapshot.medium || 0 },
            { name: "LOW", count: snapshot.low || 0 },
            { name: "INFO", count: snapshot.info || 0 }
        ]
    }

    function selectedCount(rows) {
        var count = 0
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].selected !== false)
                count += 1
        }
        return count
    }

    function queueLine() {
        if (bridge && bridge.busy) {
            var name = analysisQueue.currentName || bridge.selectedLogName || "evidence"
            var idx = analysisQueue.fileIndex || 1
            var total = analysisQueue.fileCount || Math.max(1, selectedCount(selectedEvidence))
            var phase = analysisQueue.phase || "analysing"
            var lines = analysisQueue.linesParsed || 0
            var findings = analysisQueue.findingsSaved || 0
            return "File " + idx + "/" + total + " · " + name + " · " + phase + " · " + lines + " lines · " + findings + " findings"
        }
        if (selectedEvidence.length)
            return selectedCount(selectedEvidence) + " of " + selectedEvidence.length + " queued file(s) selected for analysis"
        if (lastAnalysis.state === "complete")
            return "Completed " + (lastAnalysis.log_name || "analysis") + " with " + (lastAnalysis.total_findings || 0) + " findings"
        return "Open logs, select the files to run, then analyse the queue"
    }

    Component.onCompleted: refresh()

    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onDashboardChanged(data) {
            snapshot = data
            analysisQueue = data.analysisQueue || ({})
            historyGroups = data.historyGroups || []
        }
        function onSelectedLogChanged() { refresh() }
        function onAnalysisQueueChanged(data) { analysisQueue = data; refresh() }
        function onLastAnalysisChanged() { lastAnalysis = bridge.lastAnalysisSummary }
        function onAnalysisComplete(summary) {
            lastAnalysis = summary
            refresh()
        }
    }

    Rectangle {
        anchors.fill: parent
        color: "#080d1e"
    }

    Canvas {
        anchors.fill: parent
        opacity: 0.52
        onPaint: {
            var ctx = getContext("2d")
            ctx.reset()
            var g = ctx.createRadialGradient(width * 0.22, 80, 10, width * 0.22, 80, width * 0.8)
            g.addColorStop(0, "rgba(98,243,255,0.18)")
            g.addColorStop(0.42, "rgba(168,140,255,0.10)")
            g.addColorStop(1, "rgba(8,13,30,0)")
            ctx.fillStyle = g
            ctx.fillRect(0, 0, width, height)
            ctx.strokeStyle = "rgba(98,243,255,0.045)"
            for (var x = 0; x < width; x += 40) {
                ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke()
            }
            for (var y = 0; y < height; y += 40) {
                ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke()
            }
        }
        Component.onCompleted: requestPaint()
    }

    Flickable {
        id: scroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: Math.max(height + 1, contentColumn.implicitHeight + 56)
        clip: true

        Column {
            id: contentColumn
            width: scroll.width
            spacing: 16
            padding: 28

            C.BentoCard {
                id: hero
                width: root.cardWidth(root.columnCount())
                height: Math.max(278, heroFlow.y + heroFlow.childrenRect.height + 22)
                title: "Local-First Investigation Cockpit"
                subtitle: "Scope: " + (bridge ? bridge.sessionScopeLabel : "All Logs") + " - analyse evidence, surface findings, map attack paths, and export case artifacts locally."
                accent: "#62f3ff"

                Rectangle {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    width: Math.min(parent.width * 0.58, 720)
                    height: selectedEvidence.length ? 112 : 54
                    radius: 18
                    color: bridge && bridge.busy ? "#18365c" : "#0a1022"
                    border.color: bridge && bridge.busy ? "#62f3ff" : "#26375f"
                    clip: true

                    Rectangle {
                        id: heroSweep
                        width: 90
                        height: parent.height
                        x: -120
                        color: "#62f3ff"
                        opacity: bridge && bridge.busy ? 0.18 : 0
                    }
                    SequentialAnimation {
                        running: bridge ? (bridge.busy && !bridge.reducedMotion) : false
                        loops: Animation.Infinite
                        NumberAnimation { target: heroSweep; property: "x"; from: -120; to: 760; duration: 1050; easing.type: Easing.InOutQuad }
                    }

                    Text {
                        id: heroStatusText
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.top: parent.top
                        anchors.topMargin: selectedEvidence.length ? 13 : 18
                        text: root.queueLine()
                        color: "#eaf7ff"
                        font.pixelSize: 14
                        font.weight: Font.Bold
                        elide: Text.ElideMiddle
                    }

                    Rectangle {
                        visible: bridge ? bridge.busy : false
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.top: heroStatusText.bottom
                        anchors.topMargin: 8
                        height: 5
                        radius: 3
                        color: "#152242"
                        Rectangle {
                            width: parent.width * Math.max(0.04, Math.min(1, (analysisQueue.percent || bridge.progressValue || 0) / 100))
                            height: parent.height
                            radius: parent.radius
                            color: "#62f3ff"
                        }
                    }

                    Column {
                        visible: selectedEvidence.length > 0
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.top: heroStatusText.bottom
                        anchors.topMargin: bridge && bridge.busy ? 18 : 10
                        spacing: 5
                        Repeater {
                            model: Math.min(3, selectedEvidence.length)
                            delegate: Row {
                                required property int index
                                width: parent.width
                                height: 16
                                spacing: 8
                                Text { text: selectedEvidence[index].selected === false ? "SKIP" : "RUN"; color: selectedEvidence[index].selected === false ? "#7283a8" : "#62f3ff"; font.pixelSize: 10; font.weight: Font.Black; width: 28 }
                                Text {
                                    text: selectedEvidence[index].name || selectedEvidence[index].path || "evidence"
                                    color: "#dce8ff"
                                    font.pixelSize: 12
                                    width: parent.width - 90
                                    elide: Text.ElideMiddle
                                }
                                Text {
                                    text: (selectedEvidence[index].status || "ready") + " · " + Math.round((selectedEvidence[index].size || 0) / 1024) + " KB"
                                    color: "#8fa0c6"
                                    font.pixelSize: 11
                                    width: 92
                                    horizontalAlignment: Text.AlignRight
                                }
                            }
                        }
                        Text {
                            visible: selectedEvidence.length > 3
                            text: "+" + (selectedEvidence.length - 3) + " more queued logs"
                            color: "#ffd166"
                            font.pixelSize: 11
                            font.weight: Font.Bold
                        }
                    }
                }

                Flow {
                    id: heroFlow
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.topMargin: selectedEvidence.length ? 132 : 74
                    spacing: 10

                    C.NeonButton {
                        width: 184
                        label: bridge && bridge.busy ? "CANCEL" : "ANALYSE SELECTED"
                        accent: bridge && bridge.busy ? "#ff4d7d" : "#62f3ff"
                        primary: true
                        enabled: true
                        onClicked: bridge && bridge.busy ? bridge.cancelAnalysis() : bridge.analyseSelectedLogs()
                    }
                    C.NeonButton { label: "Analyse All"; accent: "#62f3ff"; enabled: selectedEvidence.length > 0 && (!bridge || !bridge.busy); onClicked: bridge.analyseAllLogs() }
                    C.NeonButton { label: "Open Log"; accent: "#a88cff"; onClicked: bridge.openLogDialog() }
                    C.NeonButton { label: "New Case"; accent: "#7df9c7"; onClicked: bridge.newCaseDialog() }
                    C.NeonButton { label: "Open Case"; accent: "#7df9c7"; onClicked: bridge.openCaseDialog() }
                    C.NeonButton { label: "Refresh"; accent: "#ffb74d"; onClicked: bridge.refreshSessions() }
                    C.NeonButton { label: "Export PDF"; accent: "#ffd166"; onClicked: bridge.exportReport("pdf") }
                }

                Rectangle {
                    width: 196
                    height: 144
                    radius: 30
                    color: "#0a1022"
                    border.color: sevColor(bridge ? bridge.threatLevel : "INFO")
                    anchors.right: parent.right
                    anchors.top: parent.top
                    visible: parent.width > 760

                    Text {
                        text: "THREAT"
                        color: "#8fa0c6"
                        font.pixelSize: 12
                        font.letterSpacing: 2
                        anchors.horizontalCenter: parent.horizontalCenter
                        anchors.top: parent.top
                        anchors.topMargin: 22
                    }
                    Text {
                        text: bridge ? bridge.threatLevel : "READY"
                        color: sevColor(bridge ? bridge.threatLevel : "INFO")
                        font.pixelSize: 25
                        font.weight: Font.Black
                        anchors.centerIn: parent
                    }
                    Text {
                        text: String(snapshot.maxRisk || 0) + " max risk"
                        color: "#aab9dd"
                        font.pixelSize: 12
                        anchors.horizontalCenter: parent.horizontalCenter
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 20
                    }
                }
            }

            Flow {
                id: metrics
                width: root.cardWidth(root.columnCount())
                height: childrenRect.height
                spacing: 16

                MetricTile { w: root.cardWidth(1); label: "TOTAL"; value: String(snapshot.totalFindings || 0); accent: "#62f3ff"; delay: 60 }
                MetricTile { w: root.cardWidth(1); label: "CRITICAL"; value: String(snapshot.critical || 0); accent: "#ff4d7d"; delay: 100 }
                MetricTile { w: root.cardWidth(1); label: "HIGH"; value: String(snapshot.high || 0); accent: "#ff9f43"; delay: 140 }
                MetricTile { w: root.cardWidth(1); label: "CHAINS"; value: String(snapshot.chains || 0); accent: "#a88cff"; delay: 180 }
                MetricTile { w: root.cardWidth(1); label: "RULES"; value: String(snapshot.rulesLoaded || 0); accent: "#7df9c7"; delay: 220 }
                MetricTile { w: root.cardWidth(1); label: "SESSIONS"; value: String(snapshot.sessionCount || 0); accent: "#ffd166"; delay: 260 }
            }

            Flow {
                id: dashboardGrid
                width: root.cardWidth(root.columnCount())
                height: childrenRect.height
                spacing: 16

                C.BentoCard {
                    width: root.cardWidth(2)
                    height: 240
                    title: "Severity Spectrum"
                    subtitle: "Filtering is applied directly against the case database."
                    accent: "#ffb74d"
                    revealDelay: 80

                    Column {
                        anchors.fill: parent
                        spacing: 14

                        Repeater {
                            model: root.severityModel()
                            delegate: Row {
                                required property var modelData
                                width: parent.width
                                height: 22
                                spacing: 10
                                Text {
                                    text: modelData.name
                                    width: 72
                                    color: root.sevColor(modelData.name)
                                    font.pixelSize: 11
                                    font.weight: Font.Black
                                }
                                Rectangle {
                                    width: Math.max(10, (parent.width - 132) * Math.max(0.04, modelData.count / Math.max(1, snapshot.totalFindings || 0)))
                                    height: 12
                                    radius: 6
                                    color: root.sevColor(modelData.name)
                                    opacity: 0.84
                                    anchors.verticalCenter: parent.verticalCenter
                                }
                                Text {
                                    text: String(modelData.count)
                                    color: "#eaf7ff"
                                    font.pixelSize: 12
                                    font.weight: Font.Bold
                                    anchors.verticalCenter: parent.verticalCenter
                                }
                            }
                        }

                        Flow {
                            width: parent.width
                            spacing: 8
                            Repeater {
                                model: root.severityChoices
                                delegate: C.NeonButton {
                                    required property string modelData
                                    width: 88
                                    height: 32
                                    compact: true
                                    label: modelData
                                    accent: root.sevColor(modelData)
                                    primary: bridge ? bridge.minSeverity === modelData : false
                                    onClicked: bridge.setMinSeverity(modelData)
                                }
                            }
                        }
                    }
                }

                DataCard {
                    width: root.cardWidth(1)
                    height: 240
                    title: "Top Categories"
                    accent: "#a88cff"
                    rows: snapshot.categories || []
                    nameKey: "name"
                    valueKey: "count"
                    emptyText: "Categories appear after Analyse stores detections."
                }

                EvidenceQueueCard {
                    width: root.cardWidth(1)
                    height: 260
                    rows: snapshot.selectedEvidence || []
                }

                SessionHistoryCard {
                    width: root.cardWidth(2)
                    height: 260
                    rows: snapshot.sessions || []
                    groups: snapshot.historyGroups || []
                    onOpenSession: function(sessionId) {
                        bridge.openSessionFindings(sessionId)
                        root.navigate("findings")
                    }
                    onOpenAllLogs: {
                        bridge.showAllLogs()
                        root.navigate("findings")
                    }
                }

                DataCard {
                    width: root.cardWidth(1)
                    height: 260
                    title: "MITRE Preview"
                    accent: "#7df9c7"
                    rows: snapshot.mitre || []
                    nameKey: "technique"
                    valueKey: "count"
                    emptyText: "ATT&CK techniques appear when rules map to findings."
                }

                RecentCard {
                    width: root.cardWidth(2)
                    height: 260
                    rows: snapshot.recentFindings || []
                }

                DataCard {
                    width: root.cardWidth(1)
                    height: 230
                    title: "Top Sources"
                    accent: "#62f3ff"
                    rows: (snapshot.topSources || []).map(function(item) { return { name: item, count: 1 } })
                    nameKey: "name"
                    valueKey: "count"
                    emptyText: "Source IPs and hosts appear here after analysis."
                }

                DataCard {
                    width: root.cardWidth(2)
                    height: 230
                    title: "Attack Chains"
                    accent: "#ff4d7d"
                    rows: (snapshot.attackChains || []).map(function(item) { return { name: item.chain_name || (item.categories || []).join(" -> "), count: item.finding_count || item.max_risk_score || 1 } })
                    nameKey: "name"
                    valueKey: "count"
                    emptyText: "Correlated attack chains appear when findings connect into a path."
                }
            }
        }
    }

    component MetricTile: C.BentoCard {
        property real w: 240
        property string label: ""
        property string value: "0"
        width: w
        height: 132
        title: ""
        accent: "#62f3ff"
        revealDelay: delay
        property int delay: 0

        Column {
            anchors.fill: parent
            spacing: 8
            Text {
                text: label
                color: "#8fa0c6"
                font.pixelSize: 12
                font.letterSpacing: 1.5
                font.weight: Font.Bold
            }
            Text {
                text: value
                color: "#f6fbff"
                font.pixelSize: 38
                font.weight: Font.Black
                width: parent.width
                elide: Text.ElideRight
            }
            Rectangle {
                width: parent.width * 0.62
                height: 5
                radius: 3
                color: accent
                opacity: 0.72
            }
        }
    }

    component DataCard: C.BentoCard {
        property var rows: []
        property string nameKey: "name"
        property string valueKey: "count"
        property string emptyText: "No data"

        Item {
            anchors.fill: parent
            Text {
                visible: rows && rows.length > 5
                text: "Showing " + Math.min(5, rows.length) + " of " + rows.length + " - scroll"
                color: "#7283a8"
                font.pixelSize: 10
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.topMargin: -18
            }
            Flickable {
                id: dataScroll
                anchors.fill: parent
                contentWidth: width
                contentHeight: dataColumn.height
                clip: true
                interactive: rows && rows.length > 5
                Column {
                    id: dataColumn
                    width: dataScroll.width
                    spacing: 9
                    Repeater {
                        model: rows
                        delegate: Rectangle {
                            required property var modelData
                            required property int index
                            width: parent.width
                            height: 26
                            radius: 9
                            color: index % 2 === 0 ? "#141d3a" : "#0f1730"
                            Text {
                                text: modelData[nameKey] || "-"
                                color: "#dce8ff"
                                font.pixelSize: 12
                                anchors.left: parent.left
                                anchors.leftMargin: 10
                                anchors.right: valueLabel.left
                                anchors.rightMargin: 10
                                anchors.verticalCenter: parent.verticalCenter
                                elide: Text.ElideRight
                            }
                            Text {
                                id: valueLabel
                                text: String(modelData[valueKey] || 0)
                                color: accent
                                font.pixelSize: 12
                                font.weight: Font.Black
                                anchors.right: parent.right
                                anchors.rightMargin: 10
                                anchors.verticalCenter: parent.verticalCenter
                            }
                        }
                    }
                }
            }
            Rectangle {
                visible: rows && rows.length > 5
                width: 4
                radius: 2
                color: accent
                opacity: 0.36
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.bottom: parent.bottom
            }
            C.EmptyState {
                visible: !(rows && rows.length)
                anchors.fill: parent
                title: "Waiting for evidence"
                message: emptyText
                actionLabel: "Analyse"
                accent: accent
                onAction: bridge.analyseLog()
            }
        }
    }

    component RecentCard: C.BentoCard {
        property var rows: []
        title: "Recent Findings"
        subtitle: "Newest detections from the active case/session."
        accent: "#62f3ff"

        Item {
            anchors.fill: parent
            Text {
                visible: rows && rows.length > 5
                text: "Showing " + Math.min(5, rows.length) + " of " + rows.length + " - scroll"
                color: "#7283a8"
                font.pixelSize: 10
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.topMargin: -18
            }
            Flickable {
                id: recentScroll
                anchors.fill: parent
                contentWidth: width
                contentHeight: recentColumn.height
                clip: true
                interactive: rows && rows.length > 5
                Column {
                    id: recentColumn
                    width: recentScroll.width
                    spacing: 8
                    Repeater {
                        model: rows
                        delegate: Rectangle {
                            required property var modelData
                            required property int index
                            width: parent.width
                            height: 34
                            radius: 11
                            color: index % 2 === 0 ? "#141d3a" : "#0f1730"
                            Rectangle {
                                width: 6
                                height: 20
                                radius: 3
                                color: root.sevColor(modelData.severity)
                                anchors.left: parent.left
                                anchors.leftMargin: 10
                                anchors.verticalCenter: parent.verticalCenter
                            }
                            Text {
                                text: (modelData.severity || "INFO") + "  " + (modelData.rule_name || modelData.rule_id || "finding")
                                color: "#eaf7ff"
                                font.pixelSize: 12
                                font.weight: Font.Bold
                                anchors.left: parent.left
                                anchors.leftMargin: 24
                                anchors.right: parent.right
                                anchors.rightMargin: 12
                                anchors.verticalCenter: parent.verticalCenter
                                elide: Text.ElideRight
                            }
                        }
                    }
                }
            }
            C.EmptyState {
                visible: !(rows && rows.length)
                anchors.fill: parent
                title: "No findings visible"
                message: lastAnalysis.state === "complete"
                         ? ((lastAnalysis.total_findings || 0) === 0
                            ? "Analysis completed successfully with 0 findings for the current log/scope."
                            : "Analysis completed, but no findings matched the current severity filter.")
                         : "Click Analyse to populate this detection feed."
                actionLabel: "Analyse"
                accent: "#62f3ff"
                onAction: bridge.analyseLog()
            }
        }
    }

    component EvidenceQueueCard: C.BentoCard {
        property var rows: []
        title: "Selected Evidence Queue"
        subtitle: rows.length ? (root.selectedCount(rows) + " selected / " + rows.length + " queued") : "Open one or more logs before analysis"
        accent: "#a88cff"

        Item {
            anchors.fill: parent
            Flickable {
                id: evidenceScroll
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.bottom: actionRow.top
                anchors.bottomMargin: 10
                contentWidth: width
                contentHeight: evidenceColumn.height
                clip: true
                interactive: rows.length > 3
                Column {
                    id: evidenceColumn
                    width: evidenceScroll.width
                    spacing: 8
                    Repeater {
                        model: rows
                        delegate: Rectangle {
                            required property var modelData
                            width: parent.width
                            height: 48
                            radius: 13
                            color: modelData.selected === false ? "#0c1329" : (modelData.exists ? "#141d3a" : "#351b2c")
                            border.color: modelData.selected === false ? "#26375f" : (modelData.exists ? "#2b416f" : "#ff4d7d")
                            C.NeonButton {
                                id: selectButton
                                width: 34
                                height: 28
                                compact: true
                                label: modelData.selected === false ? "○" : "✓"
                                accent: modelData.selected === false ? "#7283a8" : "#62f3ff"
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                                anchors.verticalCenter: parent.verticalCenter
                                onClicked: bridge.toggleSelectedLog(modelData.path, modelData.selected === false)
                            }
                            Text {
                                text: modelData.name || "log"
                                color: "#eaf7ff"
                                font.pixelSize: 12
                                font.weight: Font.Bold
                                anchors.left: selectButton.right
                                anchors.leftMargin: 8
                                anchors.right: removeButton.left
                                anchors.rightMargin: 8
                                y: 8
                                elide: Text.ElideMiddle
                            }
                            Text {
                                text: (modelData.status || "ready") + " · " + (modelData.lines || 0) + " lines · " + (modelData.findings || 0) + " findings"
                                color: "#91a3ca"
                                font.pixelSize: 10
                                anchors.left: selectButton.right
                                anchors.leftMargin: 8
                                anchors.right: removeButton.left
                                anchors.rightMargin: 8
                                y: 28
                                elide: Text.ElideRight
                            }
                            C.NeonButton {
                                id: removeButton
                                width: 34
                                height: 26
                                compact: true
                                label: "X"
                                accent: "#93a4c7"
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                anchors.verticalCenter: parent.verticalCenter
                                onClicked: bridge.removeSelectedLog(modelData.path)
                            }
                        }
                    }
                }
            }
            Flow {
                id: actionRow
                visible: rows.length > 0
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                spacing: 8
                C.NeonButton { label: "Open Logs"; accent: "#a88cff"; onClicked: bridge.openLogDialog() }
                C.NeonButton { label: "Analyse Selected"; width: 156; accent: "#62f3ff"; primary: true; enabled: rows.length > 0 && root.selectedCount(rows) > 0 && (!bridge || !bridge.busy); onClicked: bridge.analyseSelectedLogs() }
                C.NeonButton { label: "Analyse All"; accent: "#62f3ff"; enabled: rows.length > 0 && (!bridge || !bridge.busy); onClicked: bridge.analyseAllLogs() }
                C.NeonButton { label: "Cancel"; accent: "#ff4d7d"; visible: bridge ? bridge.busy : false; onClicked: bridge.cancelAnalysis() }
                C.NeonButton { label: "Clear"; accent: "#93a4c7"; enabled: rows.length > 0; onClicked: bridge.clearSelectedLogs() }
            }
            C.EmptyState {
                visible: !(rows && rows.length)
                anchors.fill: parent
                title: "No logs selected"
                message: "Open multiple evidence files and they will appear here before analysis starts."
                actionLabel: "Open Logs"
                accent: "#a88cff"
                onAction: bridge.openLogDialog()
            }
        }
    }

    component SessionHistoryCard: C.BentoCard {
        property var rows: []
        property var groups: []
        signal openSession(string sessionId)
        signal openAllLogs()
        title: "Analysis History"
        subtitle: rows.length ? (rows.length + " analysed log session(s)") : "Completed logs stay available in this case"
        accent: "#ffd166"

        Item {
            anchors.fill: parent
            Flickable {
                id: historyScroll
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.rightMargin: rows.length > 3 ? 10 : 0
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                contentWidth: width
                contentHeight: historyColumn.childrenRect.height + 8
                clip: true
                interactive: rows.length > 2
                boundsBehavior: Flickable.StopAtBounds
                Column {
                    id: historyColumn
                    visible: rows.length > 0
                    width: parent.width
                    spacing: 8

                    Rectangle {
                        width: parent.width
                        height: 38
                        radius: 13
                        color: bridge && bridge.currentSessionId === "" && bridge.sessionScopeLabel === "All Logs" ? "#26355f" : "#101a35"
                        border.color: bridge && bridge.currentSessionId === "" && bridge.sessionScopeLabel === "All Logs" ? "#ffd166" : "#2b416f"
                        Text { text: "All Logs"; color: "#f6fbff"; font.pixelSize: 13; font.weight: Font.Black; x: 12; anchors.verticalCenter: parent.verticalCenter }
                        C.NeonButton { width: 68; height: 26; compact: true; label: "Open"; accent: "#ffd166"; anchors.right: parent.right; anchors.rightMargin: 8; anchors.verticalCenter: parent.verticalCenter; onClicked: openAllLogs() }
                    }

                    Repeater {
                        model: (groups && groups.length) ? groups : [{ "label": "Recent", "rows": rows }]
                        delegate: Column {
                            required property var modelData
                            width: parent.width
                            spacing: 7
                            Text {
                                text: modelData.label || "Recent"
                                color: "#ffd166"
                                font.pixelSize: 11
                                font.weight: Font.Bold
                                width: parent.width
                            }
                            Repeater {
                                model: modelData.rows || []
                                delegate: Rectangle {
                                    required property var modelData
                                    width: parent.width
                                    height: 52
                                    radius: 15
                                    color: bridge && bridge.currentSessionId === modelData.id ? "#26355f" : "#101a35"
                                    border.color: bridge && bridge.currentSessionId === modelData.id ? "#ffd166" : "#2b416f"
                                    Text {
                                        text: (modelData.time ? modelData.time + "  " : "") + (modelData.name || "session")
                                        color: "#eaf7ff"
                                        font.pixelSize: 12
                                        font.weight: Font.Bold
                                        x: 12
                                        y: 8
                                        width: parent.width - 176
                                        elide: Text.ElideMiddle
                                    }
                                    Text {
                                        text: (modelData.findings || 0) + " findings · " + (modelData.entries || 0) + " lines · " + (modelData.severity || "INFO")
                                        color: "#91a3ca"
                                        font.pixelSize: 11
                                        x: 12
                                        y: 30
                                        width: parent.width - 176
                                        elide: Text.ElideRight
                                    }
                                    C.NeonButton { width: 58; height: 26; compact: true; label: "Open"; accent: "#62f3ff"; anchors.right: deleteButton.left; anchors.rightMargin: 8; anchors.verticalCenter: parent.verticalCenter; onClicked: openSession(modelData.id) }
                                    C.NeonButton { id: deleteButton; width: 58; height: 26; compact: true; label: "Delete"; accent: "#ff4d7d"; anchors.right: parent.right; anchors.rightMargin: 8; anchors.verticalCenter: parent.verticalCenter; onClicked: bridge.deleteSession(modelData.id) }
                                }
                            }
                        }
                    }
                }
            }

            Rectangle {
                visible: rows.length > 3
                width: 5
                radius: 3
                color: "#26375f"
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                opacity: 0.65
                Rectangle {
                    width: parent.width
                    radius: 3
                    color: "#ffd166"
                    height: Math.max(28, parent.height * Math.min(1, historyScroll.height / Math.max(historyScroll.contentHeight, 1)))
                    y: (parent.height - height) * Math.min(1, historyScroll.contentY / Math.max(1, historyScroll.contentHeight - historyScroll.height))
                }
            }
            C.EmptyState {
                visible: !(rows && rows.length)
                anchors.fill: parent
                title: "No analysis history"
                message: "Completed multi-log analyses will appear here and can be reopened anytime."
                actionLabel: "Open Logs"
                accent: "#ffd166"
                onAction: bridge.openLogDialog()
            }
        }
    }
}

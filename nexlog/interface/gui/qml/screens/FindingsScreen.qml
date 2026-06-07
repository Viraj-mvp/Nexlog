import QtQuick 2.15
import "../components" as C

Item {
    id: root
    property var bridge
    property string globalQuery: ""
    property var rows: []
    property var selected: ({})
    property string localQuery: ""
    property string severityFilter: "ALL"
    property var lastAnalysis: bridge ? bridge.lastAnalysisSummary : ({})
    property int pageSize: 22
    property int currentPage: 0

    function refresh() {
        if (bridge) rows = bridge.findingsSnapshot()
    }

    function sevColor(sev) {
        if (sev === "CRITICAL") return "#ff4d7d"
        if (sev === "HIGH") return "#ff9f43"
        if (sev === "MEDIUM") return "#ffd166"
        if (sev === "LOW") return "#62f3ff"
        return "#93a4c7"
    }

    function query() {
        return ((localQuery || globalQuery || "") + "").toLowerCase()
    }

    function visibleRows() {
        var q = query()
        return (rows || []).filter(function(item) {
            var sevOk = severityFilter === "ALL" || (item.severity || "INFO") === severityFilter
            var hay = [
                item.rule_name, item.rule_id, item.category, item.source_ip,
                item.hostname, item.trigger_line, item.severity
            ].join(" ").toLowerCase()
            return sevOk && (!q || hay.indexOf(q) >= 0)
        })
    }

    function pageCount() {
        return Math.max(1, Math.ceil(visibleRows().length / pageSize))
    }

    function clampPage() {
        currentPage = Math.max(0, Math.min(currentPage, pageCount() - 1))
    }

    function pageStart() {
        clampPage()
        return currentPage * pageSize
    }

    function pageEnd() {
        return Math.min(pageStart() + pageSize, visibleRows().length)
    }

    function pagedRows() {
        var filtered = visibleRows()
        clampPage()
        return filtered.slice(currentPage * pageSize, currentPage * pageSize + pageSize)
    }

    function stateLabel(item) {
        return (item.triage_state || item.state || "NEW").toString().toUpperCase()
    }

    function ruleColWidth(totalWidth) {
        return Math.max(180, totalWidth - 700)
    }

    function activeFinding() {
        if (selected && selected.finding_id) return selected
        var visible = visibleRows()
        return visible.length ? visible[0] : ({})
    }

    function ensureSelection() {
        var visible = visibleRows()
        if (!visible.length) {
            selected = ({})
            return
        }
        for (var i = 0; i < visible.length; i++) {
            if (selected && selected.finding_id && visible[i].finding_id === selected.finding_id) return
        }
        selected = visible[0]
    }

    Component.onCompleted: {
        refresh()
        ensureSelection()
    }

    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onFindingsChanged(data) { rows = data; root.currentPage = 0; root.ensureSelection() }
        function onLastAnalysisChanged() { lastAnalysis = bridge.lastAnalysisSummary }
        function onAnalysisComplete(summary) { lastAnalysis = summary; refresh(); root.ensureSelection() }
    }

    Rectangle { anchors.fill: parent; color: "#080d1e" }

    Column {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 14

        C.BentoCard {
            width: parent.width
            height: 202
            title: "Findings Triage"
            subtitle: "Scope: " + (bridge ? bridge.sessionScopeLabel : "All Logs") + " - search, filter, acknowledge, escalate, mark false-positive, and export detections."
            accent: "#62f3ff"

            Flow {
                anchors.fill: parent
                spacing: 10

                Rectangle {
                    width: Math.max(260, parent.width - 710)
                    height: 42
                    radius: 17
                    color: "#0a1022"
                    border.color: searchInput.activeFocus ? "#62f3ff" : "#26375f"
                    Text {
                        visible: !searchInput.text.length
                        text: "Search rule, source, host, trigger..."
                        color: "#596987"
                        anchors.left: parent.left
                        anchors.leftMargin: 14
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 13
                    }
                    TextInput {
                        id: searchInput
                        anchors.fill: parent
                        anchors.leftMargin: 14
                        anchors.rightMargin: 14
                        color: "#eaf7ff"
                        selectionColor: "#284c82"
                        font.pixelSize: 13
                        verticalAlignment: TextInput.AlignVCenter
                        onTextChanged: {
                            root.localQuery = text
                            root.currentPage = 0
                            root.ensureSelection()
                        }
                    }
                }

                Repeater {
                    model: ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                    delegate: C.NeonButton {
                        required property string modelData
                        width: modelData === "CRITICAL" ? 104 : 82
                        height: 42
                        compact: true
                        label: modelData
                        accent: modelData === "ALL" ? "#93a4c7" : root.sevColor(modelData)
                        primary: root.severityFilter === modelData
                        onClicked: {
                            root.severityFilter = modelData
                            root.currentPage = 0
                            root.ensureSelection()
                        }
                    }
                }

                C.NeonButton { label: "Refresh"; accent: "#ffb74d"; onClicked: { bridge.refreshSessions(); root.refresh() } }
                C.NeonButton { label: "All Logs"; accent: "#ffd166"; onClicked: bridge.showAllLogs() }
                C.NeonButton { label: "STIX"; accent: "#7df9c7"; onClicked: bridge.exportStix() }
                C.NeonButton { label: "IOC CSV"; accent: "#ffd166"; onClicked: bridge.exportIocs("csv") }
            }
        }

        Row {
            id: split
            property bool showInspector: width >= 1040
            width: parent.width
            height: parent.height - 216
            spacing: 14

            C.BentoCard {
                width: split.showInspector ? parent.width - 376 : parent.width
                height: parent.height
                title: "Detection Queue"
                subtitle: "Table view - showing " + (visibleRows().length ? (pageStart() + 1) : 0) + "-" + pageEnd() + " of " + visibleRows().length + " filtered / " + (rows ? rows.length : 0) + " total"
                accent: "#62f3ff"

                Column {
                    anchors.fill: parent
                    spacing: 8
                    visible: root.visibleRows().length > 0

                    Rectangle {
                        width: parent.width
                        height: 38
                        radius: 14
                        color: "#081022"
                        border.color: "#26375f"
                        border.width: 1
                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            height: 1
                            color: "#62f3ff"
                            opacity: 0.55
                        }
                        HeaderCell { x: 14; w: 90; label: "SEVERITY" }
                        HeaderCell { x: 104; w: 52; label: "RISK" }
                        HeaderCell { x: 160; w: root.ruleColWidth(parent.width); label: "RULE" }
                        HeaderCell { x: parent.width - 540; w: 130; label: "SOURCE" }
                        HeaderCell { x: parent.width - 398; w: 130; label: "CATEGORY" }
                        HeaderCell { x: parent.width - 252; w: 72; label: "STATE" }
                        HeaderCell { x: parent.width - 164; w: 150; label: "ACTIONS" }
                    }

                    ListView {
                        id: table
                        width: parent.width
                        height: Math.max(160, parent.height - 92)
                        clip: true
                        boundsBehavior: Flickable.StopAtBounds
                        spacing: 4
                        model: root.pagedRows()
                        delegate: Rectangle {
                            required property var modelData
                            required property int index
                            width: table.width
                            height: 42
                            radius: 13
                            color: selected.finding_id === modelData.finding_id ? "#1b2854" : (index % 2 === 0 ? "#101a34" : "#0b1329")
                            border.color: selected.finding_id === modelData.finding_id ? "#62f3ff" : "#1d2f57"
                            border.width: 1

                            Rectangle {
                                width: 5
                                height: 24
                                radius: 3
                                color: root.sevColor(modelData.severity || "INFO")
                                anchors.left: parent.left
                                anchors.leftMargin: 10
                                anchors.verticalCenter: parent.verticalCenter
                            }

                            TextCell {
                                x: 22
                                w: 82
                                textValue: modelData.severity || "INFO"
                                colorValue: root.sevColor(modelData.severity || "INFO")
                                bold: true
                            }
                            TextCell {
                                x: 104
                                w: 52
                                textValue: String(modelData.risk_score || 0)
                                colorValue: "#ffd166"
                                bold: true
                            }
                            TextCell {
                                x: 160
                                w: root.ruleColWidth(parent.width)
                                textValue: modelData.rule_name || modelData.rule_id || "finding"
                                colorValue: "#eaf7ff"
                                bold: true
                            }
                            TextCell {
                                x: parent.width - 540
                                w: 130
                                textValue: modelData.source_ip || modelData.hostname || "-"
                            }
                            TextCell {
                                x: parent.width - 398
                                w: 130
                                textValue: modelData.category || "uncategorized"
                            }
                            TextCell {
                                x: parent.width - 252
                                w: 72
                                textValue: root.stateLabel(modelData)
                                colorValue: root.stateLabel(modelData) === "ESCALATED" ? "#ff9f43" : "#93a4c7"
                            }
                            Row {
                                id: triageRow
                                spacing: 5
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                anchors.verticalCenter: parent.verticalCenter
                                z: 2
                                C.NeonButton { width: 46; height: 26; compact: true; label: "ACK"; accent: "#62f3ff"; onClicked: bridge.setFindingState(modelData.finding_id, "ACK") }
                                C.NeonButton { width: 46; height: 26; compact: true; label: "ESC"; accent: "#ff9f43"; onClicked: bridge.setFindingState(modelData.finding_id, "ESCALATE") }
                                C.NeonButton { width: 38; height: 26; compact: true; label: "FP"; accent: "#93a4c7"; onClicked: bridge.setFindingState(modelData.finding_id, "FP") }
                            }
                            MouseArea {
                                anchors.fill: parent
                                anchors.rightMargin: 164
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.selected = modelData
                            }
                        }
                    }

                    Rectangle {
                        width: parent.width
                        height: 38
                        radius: 16
                        color: "#081022"
                        border.color: "#26375f"
                        border.width: 1

                        Text {
                            text: "Page " + (root.currentPage + 1) + " / " + root.pageCount() + "  -  " + (root.visibleRows().length ? (root.pageStart() + 1) : 0) + "-" + root.pageEnd() + " visible"
                            color: "#91a3ca"
                            font.pixelSize: 12
                            anchors.left: parent.left
                            anchors.leftMargin: 14
                            anchors.verticalCenter: parent.verticalCenter
                        }
                        Row {
                            spacing: 8
                            anchors.right: parent.right
                            anchors.rightMargin: 10
                            anchors.verticalCenter: parent.verticalCenter
                            C.NeonButton {
                                width: 78
                                height: 28
                                compact: true
                                label: "Prev"
                                accent: "#93a4c7"
                                enabled: root.currentPage > 0
                                onClicked: {
                                    root.currentPage = Math.max(0, root.currentPage - 1)
                                    root.ensureSelection()
                                }
                            }
                            C.NeonButton {
                                width: 78
                                height: 28
                                compact: true
                                label: "Next"
                                accent: "#62f3ff"
                                enabled: root.currentPage < root.pageCount() - 1
                                onClicked: {
                                    root.currentPage = Math.min(root.pageCount() - 1, root.currentPage + 1)
                                    root.ensureSelection()
                                }
                            }
                        }
                    }
                }

                C.EmptyState {
                    visible: !(root.visibleRows().length)
                    anchors.fill: parent
                    title: lastAnalysis.state === "complete" ? "No matching findings" : "No findings loaded"
                    message: lastAnalysis.state === "complete"
                             ? ((lastAnalysis.total_findings || 0) === 0
                                ? "Analysis completed successfully with 0 findings for the current log/scope."
                                : "Analysis completed, but nothing matches this search/severity filter.")
                             : "Click Analyse, choose a log, and this queue will populate with backend detection results."
                    actionLabel: "Analyse"
                    accent: "#62f3ff"
                    onAction: bridge.analyseLog()
                }
            }

            C.BentoCard {
                width: 362
                height: parent.height
                visible: split.showInspector
                title: "Finding Detail"
                subtitle: "Evidence preview and analyst actions"
                accent: "#a88cff"

                Column {
                    anchors.fill: parent
                    spacing: 12

                    Text {
                        text: root.activeFinding().rule_name || root.activeFinding().rule_id || "Select a finding"
                        color: "#f4f8ff"
                        font.pixelSize: 19
                        font.weight: Font.Black
                        width: parent.width
                        wrapMode: Text.WordWrap
                    }
                    Text { text: "Severity: " + (root.activeFinding().severity || "-"); color: root.sevColor(root.activeFinding().severity || "INFO"); font.pixelSize: 13; font.weight: Font.Bold }
                    Text { text: "Category: " + (root.activeFinding().category || "-"); color: "#aab9dd"; font.pixelSize: 13; width: parent.width; elide: Text.ElideRight }
                    Text { text: "Source: " + (root.activeFinding().source_display || root.activeFinding().source_ip || root.activeFinding().hostname || "-"); color: "#aab9dd"; font.pixelSize: 13; width: parent.width; elide: Text.ElideRight }
                    Text { text: "Risk: " + (root.activeFinding().risk_score || 0); color: "#ffd166"; font.pixelSize: 13; font.weight: Font.Bold }
                    Rectangle { width: parent.width; height: 1; color: "#26375f" }
                    Text {
                        text: root.activeFinding().summary || root.activeFinding().trigger_line || "Select a finding to view the trigger preview, rule metadata, source, risk score, and triage actions."
                        color: "#dce8ff"
                        font.pixelSize: 12
                        lineHeight: 1.16
                        width: parent.width
                        wrapMode: Text.WordWrap
                    }
                    Flow {
                        width: parent.width
                        spacing: 8
                        C.NeonButton { label: "ACK"; accent: "#62f3ff"; enabled: !!root.activeFinding().finding_id; onClicked: bridge.setFindingState(root.activeFinding().finding_id, "ACK") }
                        C.NeonButton { label: "Escalate"; accent: "#ff9f43"; enabled: !!root.activeFinding().finding_id; onClicked: bridge.setFindingState(root.activeFinding().finding_id, "ESCALATE") }
                        C.NeonButton { label: "False +"; accent: "#93a4c7"; enabled: !!root.activeFinding().finding_id; onClicked: bridge.setFindingState(root.activeFinding().finding_id, "FP") }
                    }
                }
            }
        }
    }

    component HeaderCell: Text {
        property real w: 100
        property string label: ""
        width: w
        height: 38
        text: label
        color: "#7f91b8"
        font.pixelSize: 10
        font.weight: Font.Black
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }

    component TextCell: Text {
        property real w: 100
        property string textValue: ""
        property color colorValue: "#aab9dd"
        property bool bold: false
        width: w
        height: 42
        text: textValue
        color: colorValue
        font.pixelSize: 12
        font.weight: bold ? Font.Bold : Font.Normal
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
}

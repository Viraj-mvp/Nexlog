import QtQuick 2.15
import "../components" as C

Item {
    id: root
    property var bridge
    property string globalQuery: ""
    property var rows: []
    property var selected: ({})
    property string severityFilter: "ALL"
    property string sourceFilter: ""
    property int pageSize: 24
    property int currentPage: 0
    property var lastAnalysis: bridge ? bridge.lastAnalysisSummary : ({})

    function refresh() {
        if (bridge) rows = bridge.timelineSnapshot()
        ensureSelection()
    }
    function sevColor(sev) {
        if (sev === "CRITICAL") return "#ff4d7d"
        if (sev === "HIGH") return "#ff9f43"
        if (sev === "MEDIUM") return "#ffd166"
        if (sev === "LOW") return "#62f3ff"
        return "#93a4c7"
    }
    function visibleRows() {
        var q = (globalQuery || "").toLowerCase()
        var src = (sourceFilter || "").toLowerCase()
        return (rows || []).filter(function(item) {
            var sevOk = severityFilter === "ALL" || (item.severity || "INFO") === severityFilter
            var source = (item.source_display || item.source_ip || item.hostname || "").toLowerCase()
            var hay = [item.timestamp, item.rule_name, item.rule_id, item.category, source, item.summary, item.trigger_line, (item.mitre_ids || []).join(" ")].join(" ").toLowerCase()
            return sevOk && (!src || source.indexOf(src) >= 0) && (!q || hay.indexOf(q) >= 0)
        })
    }
    function pageCount() { return Math.max(1, Math.ceil(visibleRows().length / pageSize)) }
    function clampPage() { currentPage = Math.max(0, Math.min(currentPage, pageCount() - 1)) }
    function pageStart() { clampPage(); return currentPage * pageSize }
    function pageEnd() { return Math.min(pageStart() + pageSize, visibleRows().length) }
    function pagedRows() {
        var filtered = visibleRows()
        clampPage()
        return filtered.slice(currentPage * pageSize, currentPage * pageSize + pageSize)
    }
    function activeEvent() {
        if (selected && selected.finding_id) return selected
        var visible = visibleRows()
        return visible.length ? visible[0] : ({})
    }
    function ensureSelection() {
        var visible = visibleRows()
        if (!visible.length) { selected = ({}); return }
        for (var i = 0; i < visible.length; i++) {
            if (selected && selected.finding_id && visible[i].finding_id === selected.finding_id) return
        }
        selected = visible[0]
    }
    function dayBucket(ts) { return (ts || "No timestamp").slice(0, 10) }
    function timePart(ts) { return (ts || "unknown").slice(11, 19) || "unknown" }

    Component.onCompleted: refresh()
    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onTimelineChanged(data) { rows = data; root.currentPage = 0; root.ensureSelection() }
        function onAnalysisComplete(summary) { lastAnalysis = summary; refresh() }
        function onLastAnalysisChanged() { lastAnalysis = bridge.lastAnalysisSummary }
    }

    Rectangle { anchors.fill: parent; color: "#080d1e" }

    Column {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 14

        C.BentoCard {
            width: parent.width
            height: 148
            title: "Incident Timeline"
            subtitle: "Scope: " + (bridge ? bridge.sessionScopeLabel : "All Logs") + " - paged event stream with time, severity, source, rule, and evidence."
            accent: "#ffb74d"
            Flow {
                anchors.fill: parent
                spacing: 8
                Repeater {
                    model: ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                    delegate: C.NeonButton {
                        required property string modelData
                        width: modelData === "CRITICAL" ? 104 : 82
                        height: 36
                        compact: true
                        label: modelData
                        accent: modelData === "ALL" ? "#93a4c7" : root.sevColor(modelData)
                        primary: root.severityFilter === modelData
                        onClicked: { root.severityFilter = modelData; root.currentPage = 0; root.ensureSelection() }
                    }
                }
                Rectangle {
                    width: 230
                    height: 36
                    radius: 14
                    color: "#0a1022"
                    border.color: sourceInput.activeFocus ? "#ffb74d" : "#26375f"
                    Text {
                        visible: !sourceInput.text.length
                        text: "Filter source/IP..."
                        color: "#596987"
                        anchors.left: parent.left
                        anchors.leftMargin: 12
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 12
                    }
                    TextInput {
                        id: sourceInput
                        anchors.fill: parent
                        anchors.leftMargin: 12
                        anchors.rightMargin: 12
                        color: "#eaf7ff"
                        font.pixelSize: 12
                        verticalAlignment: TextInput.AlignVCenter
                        onTextChanged: { root.sourceFilter = text; root.currentPage = 0; root.ensureSelection() }
                    }
                }
                C.NeonButton { label: "Refresh"; accent: "#ffb74d"; onClicked: { bridge.refreshSessions(); root.refresh() } }
                C.NeonButton { label: "All Logs"; accent: "#ffd166"; onClicked: bridge.showAllLogs() }
                C.NeonButton { label: "PDF"; accent: "#7df9c7"; onClicked: bridge.exportReport("pdf") }
            }
        }

        Row {
            id: split
            property bool showInspector: width >= 1040
            width: parent.width
            height: parent.height - 162
            spacing: 14

            C.BentoCard {
                width: split.showInspector ? parent.width - 376 : parent.width
                height: parent.height
                title: "Event Stream"
                subtitle: "Showing " + (root.visibleRows().length ? (root.pageStart() + 1) : 0) + "-" + root.pageEnd() + " of " + root.visibleRows().length + " events"
                accent: "#ffb74d"

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
                        HeaderCell { x: 14; w: 104; label: "DAY" }
                        HeaderCell { x: 124; w: 78; label: "TIME" }
                        HeaderCell { x: 210; w: 84; label: "SEVERITY" }
                        HeaderCell { x: 304; w: 150; label: "SOURCE" }
                        HeaderCell { x: 464; w: Math.max(220, parent.width - 760); label: "RULE / CATEGORY" }
                        HeaderCell { x: parent.width - 276; w: 120; label: "MITRE" }
                        HeaderCell { x: parent.width - 148; w: 134; label: "SUMMARY" }
                    }

                    ListView {
                        id: table
                        width: parent.width
                        height: Math.max(160, parent.height - 92)
                        clip: true
                        spacing: 4
                        boundsBehavior: Flickable.StopAtBounds
                        model: root.pagedRows()
                        delegate: Rectangle {
                            required property var modelData
                            required property int index
                            width: table.width
                            height: 42
                            radius: 13
                            color: selected.finding_id === modelData.finding_id ? "#2a2547" : (index % 2 === 0 ? "#101a34" : "#0b1329")
                            border.color: selected.finding_id === modelData.finding_id ? "#ffb74d" : "#1d2f57"
                            Rectangle { width: 5; height: 24; radius: 3; color: root.sevColor(modelData.severity || "INFO"); x: 10; anchors.verticalCenter: parent.verticalCenter }
                            TextCell { x: 22; w: 96; textValue: root.dayBucket(modelData.timestamp); colorValue: "#ffcf86"; bold: true }
                            TextCell { x: 124; w: 78; textValue: root.timePart(modelData.timestamp) }
                            TextCell { x: 210; w: 84; textValue: modelData.severity || "INFO"; colorValue: root.sevColor(modelData.severity || "INFO"); bold: true }
                            TextCell { x: 304; w: 150; textValue: modelData.source_display || modelData.source_ip || modelData.hostname || "unknown" }
                            TextCell { x: 464; w: Math.max(220, parent.width - 760); textValue: (modelData.rule_name || modelData.rule_id || "event") + " / " + (modelData.category || "uncategorized"); colorValue: "#eaf7ff"; bold: true }
                            TextCell { x: parent.width - 276; w: 120; textValue: (modelData.mitre_ids || []).join(", ") || "-" }
                            TextCell { x: parent.width - 148; w: 134; textValue: modelData.summary || modelData.trigger_line || "-" }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.selected = modelData }
                        }
                    }

                    Rectangle {
                        width: parent.width
                        height: 38
                        radius: 16
                        color: "#081022"
                        border.color: "#26375f"
                        Text {
                            text: "Page " + (root.currentPage + 1) + " / " + root.pageCount()
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
                            C.NeonButton { width: 78; height: 28; compact: true; label: "Prev"; accent: "#93a4c7"; enabled: root.currentPage > 0; onClicked: { root.currentPage = Math.max(0, root.currentPage - 1); root.ensureSelection() } }
                            C.NeonButton { width: 78; height: 28; compact: true; label: "Next"; accent: "#ffb74d"; enabled: root.currentPage < root.pageCount() - 1; onClicked: { root.currentPage = Math.min(root.pageCount() - 1, root.currentPage + 1); root.ensureSelection() } }
                        }
                    }
                }

                C.EmptyState {
                    visible: !(root.visibleRows().length)
                    anchors.fill: parent
                    title: "No timeline events"
                    message: lastAnalysis.state === "complete"
                             ? ((lastAnalysis.total_findings || 0) === 0
                                ? "Analysis completed successfully with 0 findings, so no timeline events were created."
                                : "No events match the current timeline filters.")
                             : "Run Analyse to build the chronological incident stream."
                    actionLabel: "Analyse"
                    accent: "#ffb74d"
                    onAction: bridge.analyseLog()
                }
            }

            C.BentoCard {
                width: 362
                height: parent.height
                visible: split.showInspector
                title: "Event Inspector"
                subtitle: "Selected timeline evidence"
                accent: "#62f3ff"
                Column {
                    anchors.fill: parent
                    spacing: 12
                    Text { text: root.dayBucket(root.activeEvent().timestamp); color: "#ffcf86"; font.pixelSize: 18; font.weight: Font.Black; width: parent.width; elide: Text.ElideRight }
                    Text { text: root.activeEvent().rule_name || root.activeEvent().rule_id || "Select an event"; color: "#f4f8ff"; font.pixelSize: 16; font.weight: Font.Bold; width: parent.width; wrapMode: Text.WordWrap }
                    Text { text: "Source: " + (root.activeEvent().source_display || root.activeEvent().source_ip || root.activeEvent().hostname || "-"); color: "#aab9dd"; font.pixelSize: 13; width: parent.width; elide: Text.ElideRight }
                    Text { text: "Severity: " + (root.activeEvent().severity || "-"); color: root.sevColor(root.activeEvent().severity || "INFO"); font.pixelSize: 13; font.weight: Font.Bold }
                    Text { text: "MITRE: " + ((root.activeEvent().mitre_ids || []).join(", ") || "-"); color: "#7df9c7"; font.pixelSize: 13; width: parent.width; elide: Text.ElideRight }
                    Rectangle { width: parent.width; height: 1; color: "#26375f" }
                    Text { text: root.activeEvent().summary || root.activeEvent().trigger_line || "Select an event to inspect the evidence preview."; color: "#dce8ff"; font.pixelSize: 12; lineHeight: 1.16; width: parent.width; wrapMode: Text.WordWrap }
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

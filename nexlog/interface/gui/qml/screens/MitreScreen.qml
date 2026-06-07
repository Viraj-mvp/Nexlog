import QtQuick 2.15
import "../components" as C

Item {
    id: root
    property var bridge
    property string globalQuery: ""
    property var rows: []
    property var selected: ({})
    property var lastAnalysis: bridge ? bridge.lastAnalysisSummary : ({})

    function refresh() {
        if (bridge) rows = bridge.mitreSnapshot()
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
        return (rows || []).filter(function(item) {
            var hay = [item.technique, item.insight, item.evidence, (item.rules || []).join(" "), (item.sources || []).join(" ")].join(" ").toLowerCase()
            return !q || hay.indexOf(q) >= 0
        })
    }
    function activeRow() {
        if (selected && selected.technique) return selected
        var visible = visibleRows()
        return visible.length ? visible[0] : ({})
    }
    function ensureSelection() {
        var visible = visibleRows()
        if (!visible.length) { selected = ({}); return }
        for (var i = 0; i < visible.length; i++) {
            if (selected && selected.technique && visible[i].technique === selected.technique) return
        }
        selected = visible[0]
    }

    Component.onCompleted: refresh()
    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onMitreChanged(data) { rows = data; root.ensureSelection() }
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
            title: "MITRE ATT&CK Insights"
            subtitle: "Scope: " + (bridge ? bridge.sessionScopeLabel : "All Logs") + " - techniques, mapped rules, observed sources, evidence, and response guidance."
            accent: "#7df9c7"
            Flow {
                anchors.fill: parent
                spacing: 10
                C.NeonButton { label: "Refresh"; accent: "#ffb74d"; onClicked: { bridge.refreshSessions(); root.refresh() } }
                C.NeonButton { label: "All Logs"; accent: "#ffd166"; onClicked: bridge.showAllLogs() }
                C.NeonButton { label: "Findings"; accent: "#62f3ff"; onClicked: bridge.setActiveScreen("findings") }
                C.NeonButton { label: "PDF"; accent: "#7df9c7"; onClicked: bridge.exportReport("pdf") }
            }
        }

        Row {
            id: split
            property bool showInspector: width >= 1080
            width: parent.width
            height: parent.height - 162
            spacing: 14

            C.BentoCard {
                width: split.showInspector ? parent.width - 392 : parent.width
                height: parent.height
                title: "Technique Coverage"
                subtitle: root.visibleRows().length + " covered techniques with rule and source context"
                accent: "#7df9c7"

                Flickable {
                    anchors.fill: parent
                    contentWidth: width
                    contentHeight: techniqueGrid.height
                    clip: true
                    interactive: techniqueGrid.height > height
                    boundsBehavior: Flickable.StopAtBounds

                    Grid {
                        id: techniqueGrid
                        width: parent.width
                        columns: width > 980 ? 2 : 1
                        spacing: 10
                        height: childrenRect.height
                        Repeater {
                            model: root.visibleRows()
                            delegate: Rectangle {
                                required property var modelData
                                width: (techniqueGrid.width - techniqueGrid.spacing * (techniqueGrid.columns - 1)) / techniqueGrid.columns
                                height: 122
                                radius: 22
                                color: selected.technique === modelData.technique ? "#1b2a43" : "#101a35"
                                border.color: selected.technique === modelData.technique ? "#7df9c7" : "#27476d"
                                Rectangle { x: 16; y: 16; width: 8; height: 52; radius: 4; color: root.sevColor(modelData.topSeverity || "INFO") }
                                Text { text: modelData.technique || "-"; color: "#eaf7ff"; font.pixelSize: 16; font.weight: Font.Black; x: 34; y: 14; width: parent.width - 154; elide: Text.ElideRight }
                                Text { text: (modelData.count || 0) + " findings | max risk " + (modelData.maxRisk || 0); color: "#7df9c7"; font.pixelSize: 12; font.weight: Font.Bold; x: 34; y: 40; width: parent.width - 154; elide: Text.ElideRight }
                                Text { text: modelData.insight || "Technique observed in findings."; color: "#aab9dd"; font.pixelSize: 12; lineHeight: 1.1; x: 34; y: 62; width: parent.width - 52; height: 44; wrapMode: Text.WordWrap; elide: Text.ElideRight }
                                Rectangle { anchors.right: parent.right; anchors.rightMargin: 16; y: 16; width: 100; height: 28; radius: 14; color: root.sevColor(modelData.topSeverity || "INFO"); opacity: 0.18 }
                                Text { anchors.right: parent.right; anchors.rightMargin: 28; y: 22; text: modelData.topSeverity || "INFO"; color: root.sevColor(modelData.topSeverity || "INFO"); font.pixelSize: 11; font.weight: Font.Black }
                                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.selected = modelData }
                            }
                        }
                    }
                }

                C.EmptyState {
                    visible: !(root.visibleRows().length)
                    anchors.fill: parent
                    title: "No ATT&CK coverage yet"
                    message: lastAnalysis.state === "complete"
                             ? ((lastAnalysis.total_findings || 0) === 0
                                ? "Analysis completed successfully with 0 findings, so no MITRE mappings were created."
                                : "The current findings do not include MITRE mappings.")
                             : "Run Analyse to populate technique coverage."
                    actionLabel: "Analyse"
                    accent: "#7df9c7"
                    onAction: bridge.analyseLog()
                }
            }

            C.BentoCard {
                width: 378
                height: parent.height
                visible: split.showInspector
                title: "Technique Insight"
                subtitle: "Rules, sources, evidence, and response"
                accent: "#7df9c7"
                Flickable {
                    anchors.fill: parent
                    contentWidth: width
                    contentHeight: inspectorColumn.height
                    clip: true
                    interactive: inspectorColumn.height > height
                    boundsBehavior: Flickable.StopAtBounds

                    Column {
                        id: inspectorColumn
                        width: parent.width
                        spacing: 12
                        Text { text: root.activeRow().technique || "Select a technique"; color: "#f4f8ff"; font.pixelSize: 21; font.weight: Font.Black; width: parent.width; elide: Text.ElideRight }
                        Text { text: "Findings: " + (root.activeRow().count || 0) + " | Severity: " + (root.activeRow().topSeverity || "-") + " | Max risk: " + (root.activeRow().maxRisk || 0); color: root.sevColor(root.activeRow().topSeverity || "INFO"); font.pixelSize: 13; font.weight: Font.Bold; width: parent.width; wrapMode: Text.WordWrap }
                        Rectangle { width: parent.width; height: 1; color: "#26375f" }
                        Text { text: "Rules: " + ((root.activeRow().rules || []).join(", ") || "-"); color: "#dce8ff"; font.pixelSize: 12; width: parent.width; wrapMode: Text.WordWrap }
                        Text { text: "Sources: " + ((root.activeRow().sources || []).join(", ") || "-"); color: "#aab9dd"; font.pixelSize: 12; width: parent.width; wrapMode: Text.WordWrap }
                        Text { text: root.activeRow().insight || "Select a technique to view insight."; color: "#dce8ff"; font.pixelSize: 13; lineHeight: 1.16; width: parent.width; wrapMode: Text.WordWrap }
                        Text { text: "Evidence: " + (root.activeRow().evidence || "-"); color: "#91a3ca"; font.pixelSize: 12; lineHeight: 1.14; width: parent.width; wrapMode: Text.WordWrap }
                        Text { text: "Response: " + (root.activeRow().response || "-"); color: "#7df9c7"; font.pixelSize: 12; lineHeight: 1.14; width: parent.width; wrapMode: Text.WordWrap }
                    }
                }
            }
        }
    }
}

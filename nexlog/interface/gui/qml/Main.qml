import QtQuick 2.15
import QtQuick.Window 2.15
import "components" as C
import "screens" as S

Window {
    id: app
    width: 1440
    height: 900
    minimumWidth: 1180
    minimumHeight: 760
    visible: true
    title: "NexLog - Obsidian Cyber Interface"
    color: "#050712"

    property string activeScreen: "dashboard"
    property bool splashDone: false
    property bool commandOpen: false
    property bool aboutOpen: false
    property string globalQuery: ""
    property var backend: typeof appBridge === "undefined" ? null : appBridge
    property var lastAnalysis: backend ? backend.lastAnalysisSummary : ({ state: "idle", message: "No analysis run yet" })

    function screenTitle(screen) {
        if (screen === "dashboard") return "Command Center"
        if (screen === "findings") return "Findings Triage"
        if (screen === "timeline") return "Incident Timeline"
        if (screen === "graph") return "Attack Graph"
        if (screen === "ai") return "AI Query"
        if (screen === "mitre") return "MITRE Coverage"
        return "Tools Console"
    }

    function switchScreen(screen) {
        activeScreen = screen
        if (backend) backend.setActiveScreen(screen)
    }

    Connections {
        target: backend ? backend : null
        ignoreUnknownSignals: true
        function onLastAnalysisChanged() { app.lastAnalysis = app.backend.lastAnalysisSummary }
        function onAnalysisComplete(summary) {
            app.lastAnalysis = summary
            app.switchScreen("dashboard")
        }
        function onAnalysisError(message) {
            app.lastAnalysis = app.backend.lastAnalysisSummary
        }
    }

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#050712" }
            GradientStop { position: 0.45; color: "#101533" }
            GradientStop { position: 1.0; color: "#050712" }
        }
    }

    C.ParticleField {
        anchors.fill: parent
        reducedMotion: backend ? backend.reducedMotion : false
        active: splashDone && !(backend && backend.busy)
        opacity: splashDone ? 0.95 : 0.28
    }

    Rectangle {
        anchors.fill: parent
        color: "transparent"
        border.color: "#101a35"
        border.width: 1
    }

    Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true
        Keys.onPressed: function(event) {
            if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_K) {
                commandOpen = !commandOpen
                event.accepted = true
            } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_O) {
                if (app.backend) app.backend.openLogDialog()
                event.accepted = true
            } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_G) {
                switchScreen("graph")
                event.accepted = true
            } else if (event.key === Qt.Key_Escape) {
                commandOpen = false
                event.accepted = true
            }
        }
    }

    Item {
        id: shell
        anchors.fill: parent
        anchors.margins: 18
        opacity: splashDone ? 1 : 0
        scale: splashDone ? 1 : 0.985

        Behavior on opacity { NumberAnimation { duration: 420; easing.type: Easing.OutCubic } }
        Behavior on scale { NumberAnimation { duration: 520; easing.type: Easing.OutCubic } }

        C.CommandDock {
            id: dock
            bridge: app.backend
            activeScreen: app.activeScreen
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            onSelected: function(screen) { app.switchScreen(screen) }
        }

        Item {
            id: workspace
            anchors.left: dock.right
            anchors.leftMargin: 16
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.bottom: parent.bottom

            C.MissionHeader {
                id: header
                z: 8
                bridge: app.backend
                title: app.screenTitle(app.activeScreen)
                activeScreen: app.activeScreen
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                onAnalyse: {
                    if (app.backend) {
                        if (app.backend.busy) app.backend.stopAnalysis()
                        else app.backend.analyseLog()
                    }
                }
                onRefresh: if (app.backend) app.backend.refreshSessions()
                onExportPdf: if (app.backend) app.backend.exportReport("pdf")
                onPerformance: {
                    if (app.backend) {
                        app.backend.cycleHardwareMode()
                    }
                }
                onOptions: app.commandOpen = true
                onSearchChanged: function(text) { app.globalQuery = text }
            }

            C.ScannerBanner {
                id: scanner
                bridge: app.backend
                lastAnalysis: app.lastAnalysis
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: header.bottom
                anchors.topMargin: 12
            }

            Rectangle {
                id: contentFrame
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: scanner.bottom
                anchors.topMargin: 12
                anchors.bottom: parent.bottom
                radius: 32
                color: "#080d1e"
                border.color: "#223763"
                clip: true

                Loader {
                    id: screenLoader
                    anchors.fill: parent
                    sourceComponent: {
                        if (activeScreen === "dashboard") return dashboardComponent
                        if (activeScreen === "findings") return findingsComponent
                        if (activeScreen === "timeline") return timelineComponent
                        if (activeScreen === "graph") return graphComponent
                        if (activeScreen === "ai") return aiComponent
                        if (activeScreen === "mitre") return mitreComponent
                        return toolsComponent
                    }
                    onLoaded: {
                        item.opacity = 0
                        item.y = 18
                        reveal.start()
                    }
                }
            }
        }

        NumberAnimation {
            id: revealOpacity
            target: screenLoader.item
            property: "opacity"
            to: 1
            duration: app.backend && app.backend.reducedMotion ? 80 : 300
            easing.type: Easing.OutCubic
        }
        NumberAnimation {
            id: revealY
            target: screenLoader.item
            property: "y"
            to: 0
            duration: app.backend && app.backend.reducedMotion ? 80 : 340
            easing.type: Easing.OutCubic
        }
        ParallelAnimation { id: reveal; animations: [revealOpacity, revealY] }
    }

    Component { id: dashboardComponent; S.DashboardScreen { bridge: app.backend; globalQuery: app.globalQuery; onNavigate: function(screen) { app.switchScreen(screen) } } }
    Component { id: findingsComponent; S.FindingsScreen { bridge: app.backend; globalQuery: app.globalQuery } }
    Component { id: timelineComponent; S.TimelineScreen { bridge: app.backend; globalQuery: app.globalQuery } }
    Component { id: graphComponent; S.AttackGraphScreen { bridge: app.backend; globalQuery: app.globalQuery } }
    Component { id: aiComponent; S.AiScreen { bridge: app.backend; globalQuery: app.globalQuery } }
    Component { id: mitreComponent; S.MitreScreen { bridge: app.backend; globalQuery: app.globalQuery } }
    Component { id: toolsComponent; S.ToolsScreen { bridge: app.backend; globalQuery: app.globalQuery } }

    Rectangle {
        id: commandPalette
        visible: app.commandOpen
        z: 9
        anchors.fill: parent
        color: "#b0040712"

        MouseArea {
            anchors.fill: parent
            onClicked: app.commandOpen = false
        }

        Rectangle {
            width: Math.min(760, parent.width - 80)
            height: Math.min(640, parent.height - 120)
            radius: 34
            color: "#101735"
            border.color: "#62f3ff"
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 72
            clip: true

            Rectangle {
                anchors.fill: parent
                gradient: Gradient {
                    GradientStop { position: 0.0; color: "#1b2550" }
                    GradientStop { position: 0.5; color: "#101735" }
                    GradientStop { position: 1.0; color: "#080d1e" }
                }
                opacity: 0.9
            }

            Text {
                text: "Options"
                color: "#f4f8ff"
                font.pixelSize: 30
                font.weight: Font.Black
                x: 28
                y: 24
            }

            Text {
                text: "Modern access to NexLog analysis, export, AI, case, and graph workflows"
                color: "#91a3ca"
                font.pixelSize: 13
                x: 30
                y: 64
                width: parent.width - 60
                elide: Text.ElideRight
            }

            Flow {
                x: 28
                y: 110
                width: parent.width - 56
                height: parent.height - 138
                spacing: 12

                CommandItem { label: "Analyse Log"; detail: "Run the backend detector"; onPicked: app.backend.analyseLog() }
                CommandItem { label: "Open Log"; detail: "Select evidence"; onPicked: app.backend.openLogDialog() }
                CommandItem { label: "New Case"; detail: "Create .facase"; onPicked: app.backend.newCaseDialog() }
                CommandItem { label: "Open Case"; detail: "Load case DB"; onPicked: app.backend.openCaseDialog() }
                CommandItem { label: "Findings"; detail: "Triage queue"; onPicked: app.switchScreen("findings") }
                CommandItem { label: "Timeline"; detail: "Chronology"; onPicked: app.switchScreen("timeline") }
                CommandItem { label: "Attack Graph"; detail: "Path view"; onPicked: app.switchScreen("graph") }
                CommandItem { label: "MITRE"; detail: "Coverage"; onPicked: app.switchScreen("mitre") }
                CommandItem { label: "PDF Report"; detail: "Export report"; onPicked: app.backend.exportReport("pdf") }
                CommandItem { label: "STIX Bundle"; detail: "Threat intel"; onPicked: app.backend.exportStix() }
                CommandItem { label: "IOC CSV"; detail: "Indicators"; onPicked: app.backend.exportIocs("csv") }
                CommandItem { label: "Sigma"; detail: "Rule export"; onPicked: app.backend.exportSigma() }
                CommandItem { label: "UEBA"; detail: "Anomaly scan"; onPicked: app.backend.runUeba() }
                CommandItem { label: "AI Report"; detail: "Offline summary"; onPicked: app.backend.generateAiReport() }
                CommandItem { label: "Refresh"; detail: "Reload snapshots"; onPicked: app.backend.refreshSessions() }
                CommandItem { label: "Bundle"; detail: "Case archive"; onPicked: app.backend.exportCaseBundle() }
                CommandItem { label: "About NexLog"; detail: "Tool purpose, author, motto"; onPicked: app.aboutOpen = true }
            }
        }

        component CommandItem: Rectangle {
            id: cmd
            property string label: ""
            property string detail: ""
            signal picked()
            width: 164
            height: 76
            radius: 20
            color: cmdMouse.containsMouse ? "#1b2854" : "#111b3b"
            border.color: cmdMouse.containsMouse ? "#62f3ff" : "#253a70"
            Text { text: cmd.label; color: "#eaf3ff"; font.pixelSize: 14; font.weight: Font.Bold; x: 16; y: 14; width: parent.width - 32; elide: Text.ElideRight }
            Text { text: cmd.detail; color: "#91a3ca"; font.pixelSize: 12; x: 16; y: 40; width: parent.width - 32; elide: Text.ElideRight }
            MouseArea {
                id: cmdMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    app.commandOpen = false
                    cmd.picked()
                }
            }
        }
    }

    Rectangle {
        id: aboutDialog
        visible: app.aboutOpen
        z: 11
        anchors.fill: parent
        color: "#c0040712"

        MouseArea {
            anchors.fill: parent
            onClicked: app.aboutOpen = false
        }

        Rectangle {
            width: Math.min(720, parent.width - 96)
            height: 430
            radius: 34
            color: "#101735"
            border.color: "#ffd166"
            anchors.centerIn: parent
            clip: true

            MouseArea { anchors.fill: parent }

            Rectangle {
                anchors.fill: parent
                gradient: Gradient {
                    GradientStop { position: 0.0; color: "#1b2550" }
                    GradientStop { position: 0.52; color: "#101735" }
                    GradientStop { position: 1.0; color: "#080d1e" }
                }
                opacity: 0.92
            }

            Image {
                source: iconPath
                width: 76
                height: 76
                fillMode: Image.PreserveAspectFit
                x: 34
                y: 30
            }

            Text {
                text: "NexLog"
                color: "#f4f8ff"
                font.pixelSize: 34
                font.weight: Font.Black
                x: 128
                y: 34
            }

            Text {
                text: "Local-first DFIR log investigation cockpit"
                color: "#62f3ff"
                font.pixelSize: 14
                font.weight: Font.Bold
                x: 130
                y: 78
                width: parent.width - 180
                elide: Text.ElideRight
            }

            Text {
                text: "Made by Viraj Solanki"
                color: "#ffd166"
                font.pixelSize: 18
                font.weight: Font.Black
                x: 34
                y: 128
            }

            Text {
                text: "Motto: Decode logs. Defend faster."
                color: "#7df9c7"
                font.pixelSize: 15
                font.weight: Font.Bold
                x: 34
                y: 160
            }

            Text {
                text: "NexLog analyses local evidence files without sending case data to the cloud by default. It parses logs, applies detection rules, groups findings by session, builds incident timelines, maps attack paths, exports reports/IOCs/STIX/Sigma artifacts, and supports optional AI-assisted case explanation when configured."
                color: "#dce8ff"
                font.pixelSize: 14
                lineHeight: 1.22
                wrapMode: Text.WordWrap
                x: 34
                y: 208
                width: parent.width - 68
            }

            Text {
                text: "Built for fast offline triage, clean investigation history, and practical analyst workflows."
                color: "#91a3ca"
                font.pixelSize: 13
                wrapMode: Text.WordWrap
                x: 34
                y: 320
                width: parent.width - 68
            }

            Rectangle {
                width: 118
                height: 40
                radius: 20
                color: closeMouse.containsMouse ? "#1b2854" : "#111b3b"
                border.color: "#62f3ff"
                anchors.right: parent.right
                anchors.rightMargin: 28
                anchors.bottom: parent.bottom
                anchors.bottomMargin: 24
                Text {
                    anchors.centerIn: parent
                    text: "Close"
                    color: "#eaf7ff"
                    font.pixelSize: 13
                    font.weight: Font.Black
                }
                MouseArea {
                    id: closeMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: app.aboutOpen = false
                }
            }
        }
    }

    C.BrandSplash {
        id: splash
        anchors.fill: parent
        logoSource: logoPath
        reducedMotion: app.backend ? app.backend.reducedMotion : false
        statusText: app.backend ? app.backend.statusText : "Initializing parser"
        visible: !app.splashDone
        z: 10
        onFinished: app.splashDone = true
    }
}

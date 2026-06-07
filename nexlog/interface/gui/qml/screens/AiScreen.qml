import QtQuick 2.15
import "../components" as C

Item {
    id: root
    property var bridge
    property string globalQuery: ""
    property var tools: ({})
    property var aiStatus: ({})
    property var aiConfig: ({})
    property string answer: "Ask a question about the current case. NexLog stays offline-safe by default."
    property bool configOpen: false
    property bool showSecrets: false
    property string provider1: "anthropic"
    property string provider2: "gemini"
    property var providerChoices: ["anthropic", "groq", "gemini", "ollama", "openai-compatible", "custom"]

    function refresh() {
        if (!bridge) return
        tools = bridge.toolsSnapshot()
        aiStatus = bridge.aiStatusSnapshot()
        aiConfig = bridge.aiProviderConfigSnapshot()
        if (aiConfig.providers && aiConfig.providers.length > 0 && aiConfig.providers[0].provider)
            provider1 = aiConfig.providers[0].provider
        if (aiConfig.providers && aiConfig.providers.length > 1 && aiConfig.providers[1].provider)
            provider2 = aiConfig.providers[1].provider
    }

    function cycleProvider(slot) {
        var current = slot === 1 ? provider1 : provider2
        var idx = providerChoices.indexOf(current)
        var next = providerChoices[(idx + 1) % providerChoices.length]
        if (slot === 1) provider1 = next
        else provider2 = next
    }

    function saveProviderConfig() {
        if (!bridge) return
        var ok = bridge.saveAiProviderConfig({
            "provider1": provider1,
            "apiKey1": key1Input.text,
            "endpoint1": endpoint1Input.text,
            "model1": model1Input.text,
            "provider2": provider2,
            "apiKey2": key2Input.text,
            "endpoint2": endpoint2Input.text,
            "model2": model2Input.text,
            "ollamaHost": ollamaInput.text,
            "managedEndpoint": managedEndpointInput.text,
            "managedToken": managedTokenInput.text
        })
        if (ok) {
            key1Input.text = ""
            key2Input.text = ""
            managedTokenInput.text = ""
            configOpen = false
            refresh()
            answer = "AI provider settings saved locally. Keys are masked and never shown back in the UI."
        }
    }

    function providerStatusText() {
        var text = "Active: " + (aiStatus.provider || "template-synthesis")
        var providers = aiStatus.providers || []
        for (var i = 0; i < providers.length; i++) {
            var p = providers[i]
            text += "\nSlot " + p.slot + ": " + (p.label || "Not set") + " - " + (p.configured ? "configured" : "not set")
        }
        text += "\nManaged fallback: " + (aiStatus.managedConfigured ? "configured" : "not set")
        text += "\nOllama: " + (aiStatus.ollamaHost || "http://localhost:11434")
        return text
    }

    Component.onCompleted: refresh()
    Connections {
        target: bridge ? bridge : null
        ignoreUnknownSignals: true
        function onToolsChanged(data) { tools = data }
    }

    Rectangle { anchors.fill: parent; color: "#080d1e" }

    Row {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 14

        C.BentoCard {
            width: Math.max(620, parent.width - 376)
            height: parent.height
            title: "AI Case Assistant"
            subtitle: "Provider: " + (aiStatus.provider || "checking") + " - keys stay masked in local config."
            accent: "#a88cff"

            Column {
                anchors.fill: parent
                spacing: 14

                Rectangle {
                    width: parent.width
                    height: parent.height - 112
                    radius: 22
                    color: "#0a1022"
                    border.color: "#26375f"
                    clip: true
                    Flickable {
                        anchors.fill: parent
                        anchors.margins: 18
                        contentWidth: width
                        contentHeight: answerText.height
                        clip: true
                        Text {
                            id: answerText
                            width: parent.width
                            text: root.answer
                            color: "#dce8ff"
                            font.pixelSize: 14
                            lineHeight: 1.18
                            wrapMode: Text.WordWrap
                        }
                    }
                }

                Rectangle {
                    width: parent.width
                    height: 48
                    radius: 18
                    color: "#0a1022"
                    border.color: askInput.activeFocus ? "#a88cff" : "#26375f"
                    Text {
                        visible: !askInput.text.length
                        text: "Ask: What happened? What should I triage first?"
                        color: "#596987"
                        anchors.left: parent.left
                        anchors.leftMargin: 14
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 13
                    }
                    TextInput {
                        id: askInput
                        anchors.fill: parent
                        anchors.leftMargin: 14
                        anchors.rightMargin: 14
                        color: "#eaf7ff"
                        selectionColor: "#3c2b73"
                        font.pixelSize: 13
                        verticalAlignment: TextInput.AlignVCenter
                        onAccepted: {
                            root.answer = bridge.askAi(text)
                            text = ""
                            root.refresh()
                        }
                    }
                }
            }
        }

        C.BentoCard {
            width: 362
            height: parent.height
            title: "AI Controls"
            subtitle: "Lazy local workflows"
            accent: "#62f3ff"

            Column {
                anchors.fill: parent
                spacing: 10
                Text {
                    text: root.providerStatusText()
                    color: "#aab9dd"
                    font.pixelSize: 12
                    width: parent.width
                    wrapMode: Text.WordWrap
                }
                Rectangle { width: parent.width; height: 1; color: "#26375f" }
                C.NeonButton { width: parent.width; label: "Index Session"; accent: "#62f3ff"; onClicked: bridge.indexSession() }
                C.NeonButton { width: parent.width; label: "Generate AI Report"; accent: "#a88cff"; onClicked: bridge.generateAiReport() }
                C.NeonButton {
                    width: parent.width
                    label: "Configure AI Providers"
                    accent: "#ffd166"
                    primary: (aiStatus.configuredProviderCount || 0) === 0 && !aiStatus.managedConfigured
                    onClicked: { root.configOpen = true; root.refresh() }
                }
                C.NeonButton { width: parent.width; label: "Clear Chat"; accent: "#93a4c7"; onClicked: { bridge.clearAiHistory(); root.answer = "Chat cleared. Ask a new case question." } }
                Rectangle { width: parent.width; height: 1; color: "#26375f" }
                Text { text: "Suggested prompts"; color: "#f4f8ff"; font.pixelSize: 16; font.weight: Font.Black }

                Rectangle {
                    width: parent.width
                    height: Math.max(116, parent.height - 430)
                    radius: 18
                    color: "#0a1022"
                    border.color: "#26375f"
                    clip: true

                    Flickable {
                        id: promptScroll
                        anchors.fill: parent
                        anchors.margins: 10
                        contentWidth: width
                        contentHeight: promptColumn.height
                        clip: true
                        interactive: contentHeight > height
                        boundsBehavior: Flickable.StopAtBounds

                        Column {
                            id: promptColumn
                            width: promptScroll.width
                            spacing: 8
                            Repeater {
                                model: [
                                    "Summarize this case",
                                    "What are the highest-risk findings?",
                                    "What MITRE techniques appear?",
                                    "Write analyst next steps",
                                    "Explain the attack chain",
                                    "List affected hosts and sources",
                                    "Draft a containment checklist",
                                    "What evidence supports this finding?"
                                ]
                                delegate: C.NeonButton {
                                    required property string modelData
                                    width: parent.width
                                    label: modelData
                                    accent: "#7df9c7"
                                    onClicked: { root.answer = bridge.askAi(modelData); root.refresh() }
                                }
                            }
                        }
                    }
                }

                Rectangle { width: parent.width; height: 1; color: "#26375f" }
                Text { text: "Last tool: " + (tools.lastAction || "Ready"); color: "#aab9dd"; font.pixelSize: 12; width: parent.width; wrapMode: Text.WordWrap }
                Text { text: tools.lastOutput || ""; color: "#7485aa"; font.pixelSize: 11; width: parent.width; wrapMode: Text.WordWrap }
            }
        }
    }

    Rectangle {
        visible: root.configOpen
        z: 40
        anchors.fill: parent
        color: "#cc050712"

        MouseArea { anchors.fill: parent; onClicked: root.configOpen = false }

        C.BentoCard {
            id: configCard
            width: Math.min(760, parent.width - 80)
            height: Math.min(720, parent.height - 80)
            anchors.centerIn: parent
            title: "AI Provider Setup"
            subtitle: "Choose provider names and keys. Values save only to ignored .env.gui."
            accent: "#ffd166"

            MouseArea {
                anchors.fill: parent
                onClicked: function(mouse) { mouse.accepted = true }
            }

            Flickable {
                anchors.fill: parent
                contentWidth: width
                contentHeight: configColumn.height
                clip: true

                Column {
                    id: configColumn
                    width: parent.width
                    spacing: 12

                    Text {
                        text: "Configured providers: " + (aiStatus.configuredProviderCount || 0) +
                              " - Managed fallback " + (aiStatus.managedConfigured ? "yes" : "no") +
                              " - Active " + (aiStatus.provider || "template-synthesis")
                        color: "#aab9dd"
                        font.pixelSize: 12
                        width: parent.width
                        wrapMode: Text.WordWrap
                    }

                    ProviderPicker { title: "Provider Slot 1"; providerName: root.provider1; onCycle: root.cycleProvider(1) }
                    ConfigField { id: key1Input; label: "Slot 1 API key"; placeholder: "Leave blank to keep existing key"; secret: !root.showSecrets }
                    ConfigField { id: endpoint1Input; label: "Slot 1 endpoint"; placeholder: "Optional for custom/OpenAI-compatible"; secret: false }
                    ConfigField { id: model1Input; label: "Slot 1 model"; placeholder: "auto-latest"; secret: false }

                    ProviderPicker { title: "Provider Slot 2"; providerName: root.provider2; onCycle: root.cycleProvider(2) }
                    ConfigField { id: key2Input; label: "Slot 2 API key"; placeholder: "Leave blank to keep existing key"; secret: !root.showSecrets }
                    ConfigField { id: endpoint2Input; label: "Slot 2 endpoint"; placeholder: "Optional for custom/OpenAI-compatible"; secret: false }
                    ConfigField { id: model2Input; label: "Slot 2 model"; placeholder: "auto-latest"; secret: false }

                    ConfigField { id: ollamaInput; label: "Ollama host"; placeholder: aiConfig.ollamaHost || "http://127.0.0.1:11434"; secret: false }
                    ConfigField { id: managedEndpointInput; label: "Managed NexLog AI endpoint"; placeholder: aiConfig.managedConfigured ? "Already configured - leave blank to keep" : "https://your-relay.example.com/ai"; secret: false }
                    ConfigField { id: managedTokenInput; label: "Managed NexLog AI token"; placeholder: "Optional relay/license token"; secret: !root.showSecrets }

                    Text {
                        text: "NexLog never commits these values. They are written only to: " + (aiConfig.envPath || ".env.gui")
                        color: "#7283a8"
                        font.pixelSize: 11
                        width: parent.width
                        wrapMode: Text.WordWrap
                    }

                    Flow {
                        width: parent.width
                        spacing: 10
                        C.NeonButton { width: 150; label: "Save"; accent: "#62f3ff"; primary: true; onClicked: root.saveProviderConfig() }
                        C.NeonButton { width: 150; label: "Reload"; accent: "#7df9c7"; onClicked: { bridge.reloadAiProviderConfig(); root.refresh() } }
                        C.NeonButton { width: 150; label: root.showSecrets ? "Hide Keys" : "Show Keys"; accent: "#a88cff"; onClicked: root.showSecrets = !root.showSecrets }
                        C.NeonButton { width: 150; label: "Cancel"; accent: "#93a4c7"; onClicked: root.configOpen = false }
                    }
                }
            }
        }
    }

    component ProviderPicker: Item {
        property string title: ""
        property string providerName: ""
        signal cycle()
        width: parent ? parent.width : 520
        height: 44
        Row {
            anchors.fill: parent
            spacing: 10
            Text {
                width: 170
                anchors.verticalCenter: parent.verticalCenter
                text: title
                color: "#dce8ff"
                font.pixelSize: 13
                font.weight: Font.Bold
            }
            C.NeonButton {
                width: 220
                label: providerName.toUpperCase()
                accent: "#7df9c7"
                onClicked: cycle()
            }
            Text {
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - 410
                text: "Click to cycle provider"
                color: "#7283a8"
                font.pixelSize: 11
                elide: Text.ElideRight
            }
        }
    }

    component ConfigField: Item {
        property string label: ""
        property string placeholder: ""
        property bool secret: true
        property alias text: input.text
        width: parent ? parent.width : 520
        height: 68

        Text {
            text: label
            color: "#dce8ff"
            font.pixelSize: 12
            font.weight: Font.Bold
            anchors.left: parent.left
            anchors.top: parent.top
        }
        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: 42
            radius: 15
            color: "#0a1022"
            border.color: input.activeFocus ? "#ffd166" : "#26375f"
            Text {
                visible: !input.text.length
                text: placeholder
                color: "#596987"
                font.pixelSize: 12
                anchors.left: parent.left
                anchors.leftMargin: 12
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - 24
                elide: Text.ElideRight
            }
            TextInput {
                id: input
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 12
                color: "#eaf7ff"
                selectionColor: "#3c2b73"
                font.pixelSize: 13
                verticalAlignment: TextInput.AlignVCenter
                echoMode: secret ? TextInput.Password : TextInput.Normal
                clip: true
            }
        }
    }
}

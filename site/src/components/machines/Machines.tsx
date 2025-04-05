import { sleepAwait } from "sleep-await";
import LatestMachine from "./LatestMachine";

// const repo = "https://api.github.com/repos/wdeloo/HTB-Made-EZ"
const rawRepo = "https://raw.githubusercontent.com/wdeloo/HTB-Made-EZ/main"
const latestMachine = "Alert"

export interface jsonFile {
    content: string
}

export interface machine {
    difficulty: string
    name: string
    emoji: string
    os: string
    release: Date
}

// glitch effect start

function getTextElements(element: HTMLElement, textElements: ChildNode[]) {
    for (const node of element.childNodes) {
        if (node.nodeType === Node.TEXT_NODE) {
            textElements.push(node)
        } else if (node.nodeType === Node.ELEMENT_NODE) {
            getTextElements(node as HTMLElement, textElements)
        }
    }
}

function getRandomChar() {
    const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";

    const chars = [ ...letters, ...numbers ]

    return chars[Math.floor(Math.random() * chars.length)]
}

function randomizeText(text: string) {
    return text.split("").map(char => {
        const inmutableChars = [" ", "\t", "\n"]
        if (inmutableChars.includes(char)) return char

        return getRandomChar()
    }).join("")
}

export function textGlitch(element: HTMLElement) {
    if (element.dataset.glitched) return
    element.dataset.glitched = "1"

    const textElements: ChildNode[] = []

    getTextElements(element, textElements)

    textElements.forEach(async textElement => {
        if (!textElement.textContent) return

        const parent = textElement.parentElement
        if (!parent) return
        if (parent.dataset.noglitch) return

        const oldContenr = textElement.textContent

        for (let i=0; i<5; i++) {
            const newText = randomizeText(textElement.textContent)
            textElement.textContent = newText

            await sleepAwait(50)
        }

        textElement.textContent = oldContenr
        setTimeout(() => element.dataset.glitched = "", 10)
    })
}

// glitch effect end

export default function Machines() {
    return (
        <>
            <div className="w-5xl max-w-full m-auto">
                <LatestMachine latestMachine={latestMachine} rawRepo={rawRepo} />
                {/* <RecentMachines /> */}
            </div>
        </>
    )
}
import { sleepAwait } from "sleep-await";
import LatestMachine from "./LatestMachine";
import PinnedMachines from "./PinnedMachines";
import AllMachinesButton from "./AllMachinesButton";

export const REPO = "https://api.github.com/repos/wdeloo/HTB-Made-EZ/contents"
export const RAW_REPO = "https://raw.githubusercontent.com/wdeloo/HTB-Made-EZ/main"

export interface machine {
    difficulty: string
    name: string
    emoji: string
    os: string
    release: Date
}

export interface data {
    pinned: string[]
    latest: string
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

export function getDifficultyEmoji(difficulty: string) {
    switch (difficulty) {
        case "easy":
            return "🟢"
        case "medium":
            return "🟡"
        case "hard":
            return "🔴"
        case "insane":
            return "⚫️"
        default:
            return ""
    }
}

export function getOsEmoji(os: string) {
    switch (os) {
        case "linux":
            return "🐧"
        case "windows":
            return "🪟"
        case "freebsd":
            return "👿"
        case "openbsd":
            return "🐡"
        default:
            return ""
    }
}

export function getMonthName(month: number) {
    const monthNames = [ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "" ]
    return monthNames[month]
}

export async function getMachinesInfo(machineNames: string): Promise<machine>
export async function getMachinesInfo(machineNames: string[]): Promise<machine[]>
export async function getMachinesInfo(machineNames: string[] | string) {
    const getMachineInfo = async (machineName: string) => {
        const dataRes = await fetch(`${RAW_REPO}/data/${machineName}/data.json`)
        const data = await dataRes.json()

        return { difficulty: data.difficulty ?? "", name: machineName, emoji: data.emoji ?? "", os: data.os ?? "", release: new Date(data.release ?? "") }
    }

    if (typeof machineNames === "object") {
        const machines = machineNames.map(async machineName => {
            return getMachineInfo(machineName)
        })
        return await Promise.all(machines)
    } else {
        return await getMachineInfo(machineNames)
    }
}

interface machinesDir {
    name: string
    type: "dir" | "file"
}

export async function getAllMachines() {
    const res = await fetch(`${REPO}/data`)
    const json: machinesDir[] = await res.json()

    const machines = json.filter(machine => machine.type === "dir")
    const machineNames = machines.map(machine => machine.name)

    return machineNames
}

export default function Machines() {
    return (
        <div className="w-5xl max-w-full px-3 m-auto flex flex-col gap-6">
            <LatestMachine />
            <PinnedMachines />
            <AllMachinesButton />
        </div>
    )
}
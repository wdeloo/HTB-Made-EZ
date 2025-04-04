import { useEffect, useState } from "react"
import { machine } from "./Machines"
import capitalize from "capitalize"

interface props {
    latestMachine: string
    rawRepo: string
}

function getDifficultyEmoji(difficulty: string) {
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

function getOsEmoji(os: string) {
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

function getMonthName(month: number) {
    const monthNames = [ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "" ]
    return monthNames[month]
}

export default function LatestMachine({ latestMachine, rawRepo }: props) {
    const [machine, setMachine] = useState<machine | null>(null)

    useEffect(() => {
        (async () => {
            const dataRes = await fetch(`${rawRepo}/data/${latestMachine}/data.json`)
            const data = await dataRes.json()

            console.log(data.release)
            setMachine({ difficulty: data.difficulty ?? "", name: latestMachine, emoji: data.emoji ?? "", os: data.os ?? "", release: new Date(data.release ?? "") })
        })()
    }, [])

    return (
        <article>
            <a className="flex flex-row gap-8 items-stretch">
                <img width={300} src={`${rawRepo}/img/${latestMachine}/${latestMachine}.png`} />
                <div className="flex flex-col py-3">
                    <header>
                        <h1 className="text-4xl"><i><b>Latest Retired Machine</b></i></h1>
                    </header>
                    <main className="flex flex-col justify-between flex-grow">
                        <div className="py-4">
                            <h2 className="text-2xl font-bold">{machine?.emoji} {machine?.name}</h2>
                            <ul className="my-3 flex flex-row gap-4 text-lg font-bold">
                                <li>{getDifficultyEmoji(machine?.difficulty ?? "")} {capitalize(machine?.difficulty ?? "")}</li>
                                <li>{getOsEmoji(machine?.os ?? "")} {capitalize(machine?.os ?? "")}</li>
                            </ul>
                        </div>
                        <time className="text-xl font-bold opacity-60" dateTime={machine ? `${machine.release.getFullYear()}-${machine.release.getMonth()}-${machine.release.getDate()}` : undefined}>{machine?.release.getDate()} {getMonthName(machine?.release.getMonth() ?? 12)} {machine?.release.getFullYear()}</time>
                    </main>
                </div>
            </a>
        </article>
    )
}
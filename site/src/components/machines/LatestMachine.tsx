import { useContext, useEffect, useState } from "react"
import { getDifficultyEmoji, getOsEmoji, machine, RAW_REPO, textGlitch, data } from "./Machines"
import capitalize from "capitalize"
import { Link } from "react-router-dom"
import { LanguageContext } from "../../context/Languages"
import { languages } from "../languages/Languages"

export default function LatestMachine() {
    const [lang] = useContext(LanguageContext)

    const [machine, setMachine] = useState<machine | null>(null)

    useEffect(() => {
        (async () => {
            async function getLatestMachine() {
                const dataRes = await fetch(`${RAW_REPO}/data/data.json`)
                const data: data = await dataRes.json()

                const latestMachine = data.latest

                return latestMachine ?? ""
            }

            const latestMachine = await getLatestMachine()

            const dataRes = await fetch(`${RAW_REPO}/data/${latestMachine}/data.json`)
            const data = await dataRes.json()

            setMachine({ difficulty: data.difficulty ?? "", name: latestMachine, emoji: data.emoji ?? "", os: data.os ?? "", release: new Date(data.release ?? "") })
        })()
    }, [])

    if (!machine) return

    return (
        <article>
            <Link to={`/${machine.name ?? ""}`} onMouseEnter={e => textGlitch(e.currentTarget)} className="flex flex-row gap-8 items-stretch terminalText hover:bg-neutral-800">
                <img width={300} src={`${RAW_REPO}/img/${machine.name}/${machine.name}.png`} />
                <div className="flex flex-col py-3">
                    <header>
                        <h1 className="text-5xl"><b>{languages[lang].latest}</b></h1>
                    </header>
                    <main className="flex flex-col justify-between flex-grow">
                        <div className="py-4">
                            <h2 className="text-3xl font-bold"><span className="emoji" data-noglitch="1">{machine.emoji}</span> {machine.name}</h2>
                            <ul className="my-3 flex flex-row gap-4 text-xl font-bold">
                                <li><span className="emoji" data-noglitch="1">{getDifficultyEmoji(machine.difficulty)}</span> {languages[lang].difficulty[machine.difficulty as keyof typeof languages.en.difficulty]}</li>
                                <li><span className="emoji" data-noglitch="1">{getOsEmoji(machine.os)}</span> {capitalize(machine.os)}</li>
                            </ul>
                        </div>
                        <time className="text-xl font-bold opacity-60" dateTime={`${machine.release.getFullYear()}-${machine.release.getMonth()}-${machine.release.getDate()}`}>{machine.release.getDate()} {languages[lang as keyof typeof languages].getMonthName(machine.release.getMonth() ?? 12)} {machine.release.getFullYear()}</time>
                    </main>
                </div>
            </Link>
        </article>
    )
}
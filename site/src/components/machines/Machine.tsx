import capitalize from "capitalize";
import { getDifficultyEmoji, getOsEmoji, machine, RAW_REPO, textGlitch } from "./Machines";
import { Link } from "react-router-dom";
import { languages } from "../languages/Languages";
import { useContext } from "react";
import { LanguageContext } from "../../context/Languages";

interface props {
    machine: machine
    HTMLName?: string
}

export default function Machine({ machine, HTMLName }: props) {
    const [lang] = useContext(LanguageContext)

    return (
        <Link to={`/${machine.name}`} onMouseEnter={e => textGlitch(e.currentTarget)} className="flex flex-col terminalText hover:bg-neutral-800">
            <img src={`${RAW_REPO}/img/${machine.name}/${machine.name}.png`} />
            <div className="px-1 py-4 flex flex-col w-full items-center">
                <h2 className="text-2xl font-bold"><span data-noglitch="1">{machine.emoji}</span> {!HTMLName ? machine.name : <span dangerouslySetInnerHTML={{ __html: HTMLName }} />}</h2>
                <ul className="my-3 flex flex-row justify-center gap-6 text-xl font-bold w-full">
                    <li><span data-noglitch="1">{getDifficultyEmoji(machine.difficulty ?? "")}</span> {languages[lang].difficulty[machine.difficulty as keyof typeof languages.en.difficulty]}</li>
                    <li><span data-noglitch="1">{getOsEmoji(machine.os ?? "")}</span> {capitalize(machine.os ?? "")}</li>
                </ul>
                <time className=" text-lg font-bold opacity-60" dateTime={`${machine.release.getFullYear()}-${machine.release.getMonth()}-${machine.release.getDate()}`}>{machine.release.getDate()} {languages[lang as keyof typeof languages].getMonthName(machine.release.getMonth() ?? 12)} {machine.release.getFullYear()}</time>
            </div>
        </Link>
    )
}
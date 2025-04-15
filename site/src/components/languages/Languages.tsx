import { useContext, useEffect, useRef, useState } from "react"
import { LanguageContext } from "../../context/Languages"
import capitalize from "capitalize"

export const languages = {
    en: {
        emoji: "🇬🇧",
        search: "Enter Machine Name",
        latest: "Latest Retired Machine",
        difficulty: {
            easy: "Easy",
            medium: "Medium",
            hard: "Hard",
            insane: "Insane",
        },
        getMonthName(month: number) {
            return ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", ""][month]
        },
        allMachines: "Load all machines...",
    },
    es: {
        emoji: "🇪🇸",
        search: "Busca una Máquina",
        latest: "Última Máquina Retirada",
        difficulty: {
            easy: "Fácil",
            medium: "Media",
            hard: "Difícil",
            insane: "Extrema",
        },
        getMonthName(month: number) {
            return ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic", ""][month]
        },
        allMachines: "Ver todas las máquinas...",
    },
} as const

function Arrow({ menu }: { menu: boolean }) {
    return (
        <svg style={{ rotate: menu ? '180deg' : '' }} width={14} fill="currentColor" viewBox="0 0 10 5">
            <path d="M 0 0 L 10 0 L 5 5 Z" />
        </svg>
    )
}

export default function Languages() {
    const [language, setLanguage] = useContext(LanguageContext)

    const [menu, setMenu] = useState(false)

    const buttonRef = useRef<HTMLButtonElement>(null)

    useEffect(() => {
        function handleClickOutside(e: MouseEvent) {
            if (!e.target || !buttonRef.current) return
            if (buttonRef.current.contains(e.target as HTMLElement)) return

            setMenu(false)
        }

        document.addEventListener('click', handleClickOutside)

        return () => document.removeEventListener('click', handleClickOutside)
    }, [])

    const localStorageLanguage = 'lang'

    useEffect(() => {
        const lang = localStorage.getItem(localStorageLanguage)

        if (!Object.keys(languages).includes(lang ?? "")) localStorage.removeItem(localStorageLanguage)
        else setLanguage(lang as keyof typeof languages)
    }, [])

    function changeLanguage(newLanguage: keyof typeof languages) {
        setLanguage(newLanguage)
        localStorage.setItem(localStorageLanguage, newLanguage)
    }

    return (
        <div className="relative overflow-visible">
            <button ref={buttonRef} onClick={() => setMenu(prev => !prev)} className="text-2xl flex flex-row items-center gap-1.5 -mr-2 -ml-1 cursor-pointer p-1" type="button">
                {languages[language].emoji}
                <Arrow menu={menu} />
            </button>

            <ul style={{ display: menu ? '' : 'none' }} className="absolute top-full left-1/2 -translate-x-1/2 bg-[rgb(43,43,43)] shadow-lg">
                {Object.keys(languages).map((lang, i) => {
                    const key = lang as keyof typeof languages

                    return (
                        <li key={i}>
                            <button onClick={() => changeLanguage(key)} type="button" className="text-lg font-bold text-nowrap w-full px-2 py-1 hover:bg-neutral-800 cursor-pointer">
                                {languages[key].emoji} {capitalize(lang)}
                            </button>
                        </li>
                    )
                })}
            </ul>
        </div>
    )
}
import { useContext, useRef } from "react"
import { useSearchParams } from "react-router-dom"
import { LanguageContext } from "../../context/Languages"
import { languages } from "../languages/Languages"

export default function SearchBar() {
    const [lang] = useContext(LanguageContext)

    const [params] = useSearchParams()

    const inputRef = useRef<HTMLInputElement>(null)

    function handleSubmit(e: React.FormEvent) {
        e.preventDefault()

        const input = inputRef.current
        if (!input) return

        const value = input.value.trim()
        if (!value) return

        window.location.href = `${import.meta.env.BASE_URL}/#/search?q=${encodeURIComponent(value)}`
        setTimeout(() => window.location.reload(), 50)
    }

    return (
        <search>
            <form onSubmit={handleSubmit} method="GET">
                <div className="relative">
                    <input ref={inputRef} defaultValue={params.get('q') ?? ""} name="q" type="search" className="outline-none w-full text-xl px-3.5 py-2 rounded bg-neutral-800  placeholder:text-neutral-500 terminalText" placeholder={languages[lang].search} />
                    <button className="cursor-pointer" type="submit">
                        <img height={27} width={27} className="absolute right-3 top-1/2 translate-y-[-50%]" src={`${import.meta.env.BASE_URL}/img/search.svg`} />
                    </button>
                </div>
            </form>
        </search>
    )
}
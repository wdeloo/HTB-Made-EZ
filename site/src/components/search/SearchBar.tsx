import { useSearchParams } from "react-router-dom"

export default function SearchBar() {
    const [params] = useSearchParams()

    return (
        <search>
            <form action={`${import.meta.env.BASE_URL}/search`} method="GET">
                <div className="relative">
                    <input defaultValue={params.get('q') ?? ""} name="q" type="search" className="outline-none w-full text-xl px-3.5 py-2 rounded bg-neutral-800  placeholder:text-neutral-500 terminalText" placeholder="Enter Machine Name" />
                    <button className="cursor-pointer" type="submit">
                        <img height={27} width={27} className="absolute right-3 top-1/2 translate-y-[-50%]" src={`${import.meta.env.BASE_URL}/img/search.svg`} />
                    </button>
                </div>
            </form>
        </search>
    )
}
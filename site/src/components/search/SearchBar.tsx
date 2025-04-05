export default function SearchBar() {
    return (
        <search className="w-5xl px-3 max-w-full m-auto">
            <form action={`${import.meta.env.BASE_URL}/search`} method="GET">
                <div className="relative">
                    <input name="q" type="search" className="outline-none w-full text-2xl px-3.5 py-2.5 rounded bg-neutral-800 placeholder:text-neutral-500 terminalText" placeholder="Enter Machine Name" />
                    <button className="cursor-pointer" type="submit">
                        <img height={35} width={35} className="absolute right-3 top-1/2 translate-y-[-50%]" src={`${import.meta.env.BASE_URL}/img/search.svg`} />
                    </button>
                </div>
            </form>
        </search>
    )
}
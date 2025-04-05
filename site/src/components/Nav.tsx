interface SocialNetwork {
    name: string
    url: string
    icon: string
    size: number
}

const SOCIAL_NETWORKS: SocialNetwork[] = [
    { name: "GitHub", url: "https://github.com/wdeloo", icon: `${import.meta.env.BASE_URL}/img/github.png`, size: 32 },
    { name: "Hack The Box", url: "https://app.hackthebox.com/users/1130257", icon: `${import.meta.env.BASE_URL}/img/hackthebox.svg`, size: 28 },
]

export default function Nav() {
    return (
        <nav className="flex justify-center py-3">
            <ul className="w-5xl px-3 max-w-full flex flex-row justify-between items-center">
                <li className="h-full">
                    <a href={import.meta.env.BASE_URL} className="flex flex-row gap-2 items-center h-full">
                        <img src="https://www.google.com/s2/favicons?sz=64&domain=hackthebox.com" />
                        <h1 className="text-xl font-bold terminalText">HTB Made EZ</h1>
                    </a>
                </li>
                <li>
                    <ul>
                        <li className="flex flex-row items-center">
                            {SOCIAL_NETWORKS.map((socialNetwork, i) => {
                                return (
                                    <a key={i} className="h-10 w-10 flex items-center justify-center" href={socialNetwork.url} title={socialNetwork.name}>
                                        <img height={socialNetwork.size} width={socialNetwork.size} src={socialNetwork.icon} />
                                    </a>
                                )
                            })}
                        </li>
                    </ul>
                </li>
            </ul>
        </nav>
    )
}
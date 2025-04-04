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
            <ul className="w-5xl max-w-full flex flex-row justify-between items-center">
                <li className="h-full">
                    <a href={import.meta.env.BASE_URL} className="flex px-2 flex-row gap-2 items-center h-full">
                        <img src="https://www.google.com/s2/favicons?sz=64&domain=hackthebox.com" />
                        <span className="text-lg font-bold">HTB Made EZ</span>
                    </a>
                </li>
                <li>
                    <ul>
                        <li className="flex flex-row items-center">
                            {SOCIAL_NETWORKS.map(socialNetwork => {
                                return (
                                    <a className="h-10 w-10 flex items-center justify-center" href={socialNetwork.url} title={socialNetwork.name}>
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
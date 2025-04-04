import LatestMachine from "./LatestMachine";

// const repo = "https://api.github.com/repos/wdeloo/HTB-Made-EZ"
const rawRepo = "https://raw.githubusercontent.com/wdeloo/HTB-Made-EZ/main"
const latestMachine = "Alert"

export interface jsonFile {
    content: string
}

export interface machine {
    difficulty: string
    name: string
    emoji: string
    os: string
    release: Date
}

export default function Machines() {
    return (
        <>
            <div className="w-5xl max-w-full m-auto">
                <LatestMachine latestMachine={latestMachine} rawRepo={rawRepo} />
                {/* <RecentMachines /> */}
            </div>
        </>
    )
}
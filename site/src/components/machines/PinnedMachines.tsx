import { useEffect, useState } from "react"
import { machine, RAW_REPO, data, getMachinesInfo } from "./Machines"
import Machine from "./Machine"

export default function PinnedMachines() {
    const [machines, setMachines] = useState<machine[]>([])

    useEffect(() => {
        (async () => {
            async function getPinnedMachines() {
                const dataRes = await fetch(`${RAW_REPO}/data/data.json`)
                const data: data = await dataRes.json()

                const pinnedMachines = data.pinned
                if (!pinnedMachines) return []

                return pinnedMachines
            }

            const machineNames = await getPinnedMachines()

            setMachines(await getMachinesInfo(machineNames))
        })()
    }, [])

    return (
        <section aria-label="Pinned Machines">
            <ul className="flex flex-row w-full gap-2">
                {machines.map((machine, i) => {
                    return (
                        <li key={i} className="flex-1">
                            <article>
                                <Machine machine={machine} />
                            </article>
                        </li>
                    )
                })}
            </ul>
        </section>
    )
}
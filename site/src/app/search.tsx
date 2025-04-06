import { useEffect, useState } from "react"
import { getMachinesInfo, machine, REPO } from "../components/machines/Machines"
import LookFor from 'lookfor-js'
import { useSearchParams } from "react-router-dom"
import Machine from "../components/machines/Machine"

interface machinesDir {
    name: string
    type: "dir" | "file"
}

export default function Search() {
    const [machines, setMachines] = useState<{ machine: machine, highlighted: string }[]>([])
    const query = useSearchParams()[0].get('q')

    useEffect(() => {
        if (!query) return

        const getAllMachines = async () => {
            const res = await fetch(`${REPO}/data`)
            const json: machinesDir[] = await res.json()

            const machines = json.filter(machine => machine.type === "dir")
            const machineNames = machines.map(machine => machine.name)

            return machineNames
        }

        (async () => {
            const machines = await getAllMachines()

            const lookfor = new LookFor({ tag: "mark" }, { keySensitive: false, detectAccents: false })
            const highlightedMachines = machines.map(machine => {
                const highlighted = lookfor.highlight(machine, query)
                if (highlighted === machine) return null
                return { highlighted, machine }
            }).filter(machine => machine !== null)

            const machinesProm = highlightedMachines.map(async machine => { return { machine: await getMachinesInfo(machine.machine), highlighted: machine.highlighted } })
            Promise.all(machinesProm).then(machines => setMachines(machines))
        })()
    }, [])

    return (
        <main>
            <section className="w-5xl px-3 max-w-full m-auto">
                <ul className="grid grid-cols-4 gap-2">
                    {machines.map((machine, i) => {
                        return (
                            <li key={i}>
                                <article>
                                    <Machine machine={machine.machine} HTMLName={machine.highlighted} />
                                </article>
                            </li>
                        )
                    })
                    }
                </ul>
            </section>
        </main>
    )
}
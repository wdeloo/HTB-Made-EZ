import { useEffect, useState } from "react"
import { getAllMachines, getMachinesInfo, machine } from "../components/machines/Machines"
import LookFor from 'lookfor-js'
import { useSearchParams } from "react-router-dom"
import Machine from "../components/machines/Machine"

export default function Search() {
    const [machines, setMachines] = useState<{ machine: machine, highlighted: string }[]>([])
    const query = useSearchParams()[0].get('q')

    useEffect(() => {
        if (!query) return

        (async () => {
            const machines = await getAllMachines()

            const lookfor = new LookFor({ tag: "mark" }, { keySensitive: false, detectAccents: false })
            const highlightedMachines = machines.map(machine => {
                const highlighted = lookfor.highlight(machine, query)
                if (highlighted === machine) return null
                return { highlighted, machine }
            }).filter(machine => machine !== null)

            let machinesInfo: { machine: machine, highlighted: string }[] = []
            for (let i = 0; i < machines.length; i += 4) {
                const machinesProm = highlightedMachines.slice(i, i + 4).map(async machine => { return { machine: await getMachinesInfo(machine.machine), highlighted: machine.highlighted } })
                Promise.all(machinesProm).then(machines => {
                    machinesInfo = machinesInfo.concat(machines)
                    setMachines(machinesInfo)
                })
            }
        })()
    }, [])

    return (
        <main className="py-6">
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
                    })}
                </ul>
            </section>
        </main>
    )
}
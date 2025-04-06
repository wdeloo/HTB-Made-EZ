import { useEffect, useState } from "react"
import { getAllMachines, getMachinesInfo, machine } from "../components/machines/Machines"
import Machine from "../components/machines/Machine"

export default function Machines() {
    const [machines, setMachines] = useState<machine[]>([])

    useEffect(() => {
        (async () => {
            const machines = await getAllMachines()
            const machinesInfo = await getMachinesInfo(machines)

            setMachines(machinesInfo)
        })()
    })

    return (
        <main className="py-6">
            <section className="w-5xl px-3 max-w-full m-auto">
                <ul className="grid grid-cols-4 gap-2">
                    {machines.map((machine, i) => {
                        return (
                            <li key={i}>
                                <article>
                                    <Machine machine={machine} />
                                </article>
                            </li>
                        )
                    })}
                </ul>
            </section>
        </main>
    )
}
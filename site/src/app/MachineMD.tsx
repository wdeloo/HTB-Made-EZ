import { useEffect, useState } from "react"
import { useParams } from "react-router-dom"
import { RAW_REPO } from "../components/machines/Machines"
import Terminal, { Code } from "../components/markdown/Terminal"
import Markdown from "markdown-to-jsx"
import Title, { Heading, Section } from "../components/markdown/Headings"
import Image from "../components/markdown/Image"
import Line from "../components/markdown/Lines"
import Link from "../components/markdown/Links"

export default function MachineMD() {
    const [content, setContent] = useState("")

    const { name } = useParams()

    useEffect(() => {
        (async () => {
            const res = await fetch(`${RAW_REPO}/en/${name}/readme.md`)
            const content = await res.text()

            setContent(content)
        })()
    }, [])

    return (
        <main className="pt-2 pb-6">
            <section className="w-5xl max-w-full px-3 m-auto text-lg">
                <Markdown
                    options={{
                        overrides: {
                            pre: Terminal,
                            code: Code,
                            h1: Title,
                            h2: Section,
                            h3: Heading,
                            img: Image,
                            hr: Line,
                            a: Link,
                        }
                    }}
                >
                    {content}
                </Markdown>
            </section>
        </main>
    )
}
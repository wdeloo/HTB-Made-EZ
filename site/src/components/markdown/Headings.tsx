import { Link } from "react-router-dom"

export default function Title({ children, id }: { children: React.ReactNode, id: string }) {
    return (
        <h1 id={id} className="text-5xl font-bold w-fit text-center relative mx-auto group px-12 my-6 text-balance scroll-mt-24">
            <Link to={`#${id}`} className="text-3xl text-[#9fef00] font-extrabold absolute left-4 top-[50%] translate-y-[-50%] hidden group-hover:block" type="button">#</Link>
            {children}
        </h1>
    )
}

export function Section({ children, id }: { children: React.ReactNode, id: string }) {
    return (
        <>
            <h2 id={id} className="text-4xl font-bold pl-6.5 group relative my-3">
                <Link to={`#${id}`} className="text-2xl group-hover:text-[#9fef00] text-neutral-500 font-extrabold absolute left-0 top-[50%] translate-y-[-50%]" type="button">#</Link>
                {children}
            </h2>
            <hr className="border-neutral-600 mb-3" />
        </>
    )
}

export function Heading({ children, id }: { children: React.ReactNode, id: string }) {
    return (
        <>
            <h2 id={id} className="text-2xl font-bold pl-5 group relative my-2">
                <Link to={`#${id}`} className="text-xl group-hover:text-[#9fef00] text-neutral-500 font-extrabold absolute left-0 top-[50%] translate-y-[-50%]" type="button">#</Link>
                {children}
            </h2>
        </>
    )
}
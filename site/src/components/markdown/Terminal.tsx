import { useState } from "react"

export function WindowManagers({ toggleMinimized }: { toggleMinimized: () => void }) {
    return (
        <div className="flex flex-row gap-2">
            <button onClick={toggleMinimized} type="button">
                <CloseSVG />
            </button>
            <button onClick={toggleMinimized} type="button">
                <MinimizeSVG />
            </button>
            <button onClick={toggleMinimized} type="button">
                <FullSVG />
            </button>
        </div>
    )
}

export function Code({ children }: { children: React.ReactNode }) {
    return (
        <code className="terminalText text-xl bg-[#202020] px-2 py-0.5 rounded shadow-xs shadow-neutral-900 mx-0.5">
            {children}
        </code>
    )
}

function CloseSVG() {
    return (
        <svg className="group" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="12" fill="#ff0000" />
            <g clipPath="url(#clip0_429_11083)">
                <path d="M7 7.00006L17 17.0001M7 17.0001L17 7.00006" className="group-hover:stroke-[#000000] opacity-50" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
            </g>
            <defs>
                <clipPath id="clip0_429_11083">
                    <rect width="24" height="24" fill="white" />
                </clipPath>
            </defs>
        </svg>
    )
}

function MinimizeSVG() {
    return (
        <svg className="group" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="12" fill="#ffae00" />
            <line x1="6" x2="18" y1="12" y2="12" className="group-hover:stroke-[#000000] opacity-50" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    )
}

function FullSVG() {
    return (
        <svg className="group" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="12" fill="#08ca3e" />
            <path d="M 17 13 L 17 7 L 11 7 Z" className="group-hover:stroke-[#000000] group-hover:fill-[#000000] opacity-50" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M 7 11 L 7 17 L 13 17 Z" className="group-hover:stroke-[#000000] group-hover:fill-[#000000] opacity-50" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    )
}

function CopySVG({ copied }: { copied: boolean }) {
    return (
        <>
            <svg style={{ display: copied ? 'none' : '' }} className="my-[-2px] scale-x-[-100%] group" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M3 16V4C3 2.89543 3.89543 2 5 2H15M9 22H18C19.1046 22 20 21.1046 20 20V8C20 6.89543 19.1046 6 18 6H9C7.89543 6 7 6.89543 7 8V20C7 21.1046 7.89543 22 9 22Z" className="opacity-50 group-hover:opacity-100" stroke="#ffffff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <svg style={{ display: !copied ? 'none' : '' }} className="my-[-2px] group rotate-45 translate-y-[-10%]" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M 9 20 L 17 20 L 17 5" stroke="#ffffff" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
        </>
    )
}

export default function Terminal({ children }: { children: React.ReactNode }) {
    const [minimized, setMinimized] = useState(false)
    const [copied, setCopied] = useState(false)

    const jsxChildren = children as React.JSX.Element

    function toggleMinimized() {
        setMinimized(prev => !prev)
    }

    async function copyContent() {
        setCopied(true)
        setTimeout(() => setCopied(false), 3000)

        if (!children) return

        await navigator.clipboard.writeText(jsxChildren.props.children)
    }

    return (
        <div className="bg-[#202020] rounded-lg px-4 shadow shadow-neutral-900 my-4">
            <div className="flex flex-row justify-between items-center pb-3 pt-4 relative">
                <WindowManagers toggleMinimized={toggleMinimized} />
                <span className="terminalText absolute left-1/2 translate-x-[-50%] text-white opacity-50">{jsxChildren.props.className ? `#!/langs/${(jsxChildren.props.className as string).replace('lang-', '')}` : '/home/delo'}</span>
                <button onClick={copyContent} type="button">
                    <CopySVG copied={copied} />
                </button>
            </div>
            <pre style={{ display: minimized ? 'none' : '' }} className="overflow-x-auto pb-2 *:px-0 *:py-0 *:shadow-none *:mx-0">
                {children}
            </pre>
        </div>
    )
}
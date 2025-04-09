export default function Link({ children, href }: { children: React.ReactNode, href: string }) {
    return (
        <a href={href} className="text-[#9fef00] hover:underline">
            {children}
        </a>
    )
}
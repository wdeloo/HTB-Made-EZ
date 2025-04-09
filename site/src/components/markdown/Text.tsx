export default function Paragraph({ children }: { children: React.ReactNode }) {
    return (
        <p className="my-3">
            {children}
        </p>
    )
}
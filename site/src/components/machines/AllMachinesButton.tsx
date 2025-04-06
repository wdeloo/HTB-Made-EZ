export default function AllMachinesButton() {
    return (
        <a href={`${import.meta.env.BASE_URL}/machines`} className="terminalText text-2xl m-auto px-10 py-6 hover:underline">
            Load all machines...
        </a>
    )
}
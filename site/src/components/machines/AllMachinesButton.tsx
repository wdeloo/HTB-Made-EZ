import { Link } from "react-router-dom";

export default function AllMachinesButton() {
    return (
        <Link to="/machines" className="terminalText text-2xl mx-auto mt-5 px-10 py-6 hover:underline">
            Load all machines...
        </Link>
    )
}
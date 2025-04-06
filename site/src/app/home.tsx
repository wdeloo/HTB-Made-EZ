import Machines from "../components/machines/Machines";
import SearchBar from "../components/search/SearchBar";

export default function Home() {
    return (
        <>    
            <main className="flex flex-col py-4 gap-12">
                <SearchBar />
                <Machines />
            </main>
    
            {/* <footer>
    
            </footer> */}
        </>
    )
}
import { Route, Routes } from 'react-router-dom'
import './App.css'
import Home from './app/home'
import Search from './app/search'
import Nav from './components/Nav'
import Machines from './app/machines'
import MachineMD from './app/MachineMD'

export default function App() {
    return (
        <>
            <header className="z-[999] sticky top-0">
                <Nav />
            </header>
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/search" element={<Search />} />
                <Route path="/machines" element={<Machines />} />
                <Route path="/:name" element={<MachineMD />} />
            </Routes>
        </>
    )
}
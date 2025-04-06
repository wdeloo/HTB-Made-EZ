import { Route, Routes } from 'react-router-dom'
import './App.css'
import Home from './app/home'
import Search from './app/search'
import Nav from './components/Nav'
import Machines from './app/machines'
import MachineMD from './app/MachineMD'

function App() {
    return (
        <>
            <header className="z-[999] sticky top-0">
                <Nav />
            </header>
            <Routes>
                <Route path={`${import.meta.env.BASE_URL}/`} element={<Home />} />
                <Route path={`${import.meta.env.BASE_URL}/search`} element={<Search />} />
                <Route path={`${import.meta.env.BASE_URL}/machines`} element={<Machines />} />
                <Route path={`${import.meta.env.BASE_URL}/:name`} element={<MachineMD />} />
            </Routes>
        </>
    )
}

export default App

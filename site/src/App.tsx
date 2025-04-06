import { Route, Routes } from 'react-router-dom'
import './App.css'
import Home from './app/home'
import Search from './app/search'
import Nav from './components/Nav'

function App() {
    return (
        <>
            <header className="z-[999] sticky top-0">
                <Nav />
            </header>
            <Routes>
                <Route path={`${import.meta.env.BASE_URL}/`} element={<Home />} />
                <Route path={`${import.meta.env.BASE_URL}/search`} element={<Search />} />
            </Routes>
        </>
    )
}

export default App

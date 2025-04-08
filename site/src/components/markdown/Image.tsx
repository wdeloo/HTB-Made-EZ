import { useState } from "react";
import { RAW_REPO } from "../machines/Machines";
import { WindowManagers } from "./Terminal";

function Arrow({ width, rotate, className, size }: { width: number, rotate: number, className: string, size: number }) {
    return (
        <svg style={{ rotate: `${rotate}deg` }} className="overflow-visible group" width={`${size}px`} height={`${size}px`} viewBox="0 -4.5 20 20" version="1.1" xmlns="http://www.w3.org/2000/svg">
            <g id="Page-1" className={className} strokeWidth={width} fill="none" fillRule="evenodd">
                <g id="Dribbble-Light-Preview" transform="translate(-220.000000, -6684.000000)" fill="#000000">
                    <g id="icons" transform="translate(56.000000, 160.000000)">
                        <path d="M164.292308,6524.36583 L164.292308,6524.36583 C163.902564,6524.77071 163.902564,6525.42619 164.292308,6525.83004 L172.555873,6534.39267 C173.33636,6535.20244 174.602528,6535.20244 175.383014,6534.39267 L183.70754,6525.76791 C184.093286,6525.36716 184.098283,6524.71997 183.717533,6524.31405 C183.328789,6523.89985 182.68821,6523.89467 182.29347,6524.30266 L174.676479,6532.19636 C174.285736,6532.60124 173.653152,6532.60124 173.262409,6532.19636 L165.705379,6524.36583 C165.315635,6523.96094 164.683051,6523.96094 164.292308,6524.36583" id="arrow_down-[#338]">

                        </path>
                    </g>
                </g>
            </g>
        </svg>
    )
}

function Download({ src }: { src: string }) {
    return (
        <a href={src} download="image.png" className="mr-[3px] flex items-center justify-center mx-0.5">
            <Arrow width={3} rotate={0} className="stroke-[#202020]" size={16} />
        </a>
    )
}

function BackForward() {
    return (
        <div className="flex flex-row gap-3">
            <Arrow width={2} rotate={90} className="stroke-[#464646] group-hover:stroke-[#101010]" size={12} />
            <Arrow width={2} rotate={-90} className="stroke-[#464646] group-hover:stroke-[#101010]" size={12} />
        </div>
    )
}

function SearchBar() {
    return (
        <div className="flex-grow flex flex-row items-center px-1 gap-1 rounded-full bg-neutral-300 hover:bg-[#c4c4c4] h-full transition cursor-text">
            <svg width="14px" height="14px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M13.3891 13.3891L19 19M9.5 15C12.5376 15 15 12.5376 15 9.5C15 6.46243 12.5376 4 9.5 4C6.46243 4 4 6.46243 4 9.5C4 12.5376 6.46243 15 9.5 15Z" stroke="#464646" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
        </div>
    )
}

export default function Image({ src, alt }: { src: string, alt: string }) {
    const [imgWidth, setImgWidth] = useState(0)
    const [minimized, setMinimized] = useState(false)

    function toggleMinimized() {
        setMinimized(prev => !prev)
    }

    const imgSrc = src.replace("../..", RAW_REPO)

    return (
        <div className="flex flex-row justify-center">
            <div style={{ minWidth: imgWidth + (12 * 2) }} className="mx-16 my-4 bg-white p-3 w-fit rounded-lg shadow shadow-neutral-900 flex flex-col gap-3">
                <div className="flex flex-row items-center w-full justify-between gap-2">
                    <WindowManagers toggleMinimized={toggleMinimized} />
                    <BackForward />
                    <SearchBar />
                    <Download src={imgSrc} />
                </div>

                <img onLoad={e => setImgWidth(e.currentTarget.width)} style={{ display: minimized ? 'none' : '' }} className="rounded-lg" src={imgSrc} alt={alt} />
            </div>
        </div>
    )
}
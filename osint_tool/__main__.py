"""Start the supported desktop application."""
import multiprocessing

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from osint_tool.desktop.app import main
    main()

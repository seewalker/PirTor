
void mk( ) {
    string dbdir = pir_db_path;
    if ( ! mkdb_from_file(DESC,"cached-descriptors",(dbdir + "/desc").c_str())) {
        cerr << "Failed to make desc db" << endl;
        return EXIT_FAILURE;
    }
    else {
        cout << "Make desc db successfully" << endl;
    }
    if ( ! mkdb_from_file(MICRODESC,"cached-microdesc",(dbdir + "/microdesc").c_str())) {
        cerr << "Failed to make microdesc db" << endl;
        return EXIT_FAILURE;
    }
    else {
        cout << "Make microdesc db successfully" << endl;
    }
}

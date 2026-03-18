.class public final Lnet/zetetic/database/sqlcipher/SQLiteStatement;
.super Lnet/zetetic/database/sqlcipher/SQLiteProgram;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/sqlite/db/SupportSQLiteStatement;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, p3, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public execute()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-virtual {v0, v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->execute(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :catchall_0
    move-exception v0

    .line 29
    goto :goto_0

    .line 30
    :catch_0
    move-exception v0

    .line 31
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 32
    .line 33
    .line 34
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 35
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 36
    .line 37
    .line 38
    throw v0
.end method

.method public executeInsert()J
    .locals 5

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-virtual {v0, v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeForLastInsertedRowId(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 26
    .line 27
    .line 28
    return-wide v0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    goto :goto_0

    .line 31
    :catch_0
    move-exception v0

    .line 32
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 33
    .line 34
    .line 35
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public executeRaw()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-virtual {v0, v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeRaw(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :catchall_0
    move-exception v0

    .line 29
    goto :goto_0

    .line 30
    :catch_0
    move-exception v0

    .line 31
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 32
    .line 33
    .line 34
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 35
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 36
    .line 37
    .line 38
    throw v0
.end method

.method public executeUpdateDelete()I
    .locals 5

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-virtual {v0, v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeForChangedRowCount(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)I

    .line 22
    .line 23
    .line 24
    move-result v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 26
    .line 27
    .line 28
    return v0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    goto :goto_0

    .line 31
    :catch_0
    move-exception v0

    .line 32
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 33
    .line 34
    .line 35
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public simpleQueryForBlobFileDescriptor()Landroid/os/ParcelFileDescriptor;
    .locals 5

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-virtual {v0, v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeForBlobFileDescriptor(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;

    .line 22
    .line 23
    .line 24
    move-result-object v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 26
    .line 27
    .line 28
    return-object v0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    goto :goto_0

    .line 31
    :catch_0
    move-exception v0

    .line 32
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 33
    .line 34
    .line 35
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public simpleQueryForLong()J
    .locals 5

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-virtual {v0, v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 26
    .line 27
    .line 28
    return-wide v0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    goto :goto_0

    .line 31
    :catch_0
    move-exception v0

    .line 32
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 33
    .line 34
    .line 35
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public simpleQueryForString()Ljava/lang/String;
    .locals 5

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-virtual {v0, v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeForString(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 26
    .line 27
    .line 28
    return-object v0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    goto :goto_0

    .line 31
    :catch_0
    move-exception v0

    .line 32
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 33
    .line 34
    .line 35
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SQLiteProgram: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

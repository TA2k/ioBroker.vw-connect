.class public final Lnet/zetetic/database/sqlcipher/SQLiteQuery;
.super Lnet/zetetic/database/sqlcipher/SQLiteProgram;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "SQLiteQuery"


# instance fields
.field private final mCancellationSignal:Landroid/os/CancellationSignal;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;Landroid/os/CancellationSignal;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 3
    .line 4
    .line 5
    iput-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteQuery;->mCancellationSignal:Landroid/os/CancellationSignal;

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public fillWindow(Lnet/zetetic/database/CursorWindow;IIZ)I
    .locals 11

    .line 1
    const-string v1, "exception: "

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    .line 9
    :try_start_1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getBindArgs()[Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getConnectionFlags()I

    .line 22
    .line 23
    .line 24
    move-result v9

    .line 25
    iget-object v10, p0, Lnet/zetetic/database/sqlcipher/SQLiteQuery;->mCancellationSignal:Landroid/os/CancellationSignal;
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_1 .. :try_end_1} :catch_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 26
    .line 27
    move-object v5, p1

    .line 28
    move v6, p2

    .line 29
    move v7, p3

    .line 30
    move v8, p4

    .line 31
    :try_start_2
    invoke-virtual/range {v2 .. v10}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeForCursorWindow(Ljava/lang/String;[Ljava/lang/Object;Lnet/zetetic/database/CursorWindow;IIZILandroid/os/CancellationSignal;)I

    .line 32
    .line 33
    .line 34
    move-result p1
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 35
    :try_start_3
    invoke-virtual {v5}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 39
    .line 40
    .line 41
    return p1

    .line 42
    :catchall_0
    move-exception v0

    .line 43
    move-object p1, v0

    .line 44
    goto :goto_6

    .line 45
    :catchall_1
    move-exception v0

    .line 46
    :goto_0
    move-object p1, v0

    .line 47
    goto :goto_5

    .line 48
    :catch_0
    move-exception v0

    .line 49
    :goto_1
    move-object p1, v0

    .line 50
    goto :goto_3

    .line 51
    :catch_1
    move-exception v0

    .line 52
    :goto_2
    move-object p1, v0

    .line 53
    goto :goto_4

    .line 54
    :catchall_2
    move-exception v0

    .line 55
    move-object v5, p1

    .line 56
    goto :goto_0

    .line 57
    :catch_2
    move-exception v0

    .line 58
    move-object v5, p1

    .line 59
    goto :goto_1

    .line 60
    :catch_3
    move-exception v0

    .line 61
    move-object v5, p1

    .line 62
    goto :goto_2

    .line 63
    :goto_3
    :try_start_4
    const-string p2, "SQLiteQuery"

    .line 64
    .line 65
    new-instance p3, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    invoke-direct {p3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p4

    .line 74
    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string p4, "; query: "

    .line 78
    .line 79
    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->getSql()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p4

    .line 86
    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p3

    .line 93
    invoke-static {p2, p3}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p1

    .line 97
    :goto_4
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 98
    .line 99
    .line 100
    throw p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 101
    :goto_5
    :try_start_5
    invoke-virtual {v5}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 102
    .line 103
    .line 104
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 105
    :goto_6
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 106
    .line 107
    .line 108
    throw p1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SQLiteQuery: "

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

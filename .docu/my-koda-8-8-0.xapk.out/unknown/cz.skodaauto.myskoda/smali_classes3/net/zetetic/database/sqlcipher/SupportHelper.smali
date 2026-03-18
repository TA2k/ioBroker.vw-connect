.class public Lnet/zetetic/database/sqlcipher/SupportHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/sqlite/db/SupportSQLiteOpenHelper;


# instance fields
.field private openHelper:Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;


# direct methods
.method public constructor <init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V
    .locals 6

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    .line 1
    invoke-direct/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SupportHelper;-><init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZI)V

    return-void
.end method

.method public constructor <init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZI)V
    .locals 12

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;

    iget-object v2, p1, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->a:Landroid/content/Context;

    iget-object v3, p1, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->b:Ljava/lang/String;

    iget-object v1, p1, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->c:Lb11/a;

    iget v6, v1, Lb11/a;->e:I

    const/4 v8, 0x0

    const/4 v5, 0x0

    move-object v1, p0

    move-object v11, p1

    move-object v4, p2

    move-object v9, p3

    move/from16 v10, p4

    move/from16 v7, p5

    invoke-direct/range {v0 .. v11}, Lnet/zetetic/database/sqlcipher/SupportHelper$1;-><init>(Lnet/zetetic/database/sqlcipher/SupportHelper;Landroid/content/Context;Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZLandroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;)V

    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper;->openHelper:Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;

    return-void
.end method


# virtual methods
.method public close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper;->openHelper:Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getDatabaseName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper;->openHelper:Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getDatabaseName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getReadableDatabase()Landroidx/sqlite/db/SupportSQLiteDatabase;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper;->openHelper:Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getReadableDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getWritableDatabase()Landroidx/sqlite/db/SupportSQLiteDatabase;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper;->openHelper:Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getWritableDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public setWriteAheadLoggingEnabled(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper;->openHelper:Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->setWriteAheadLoggingEnabled(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

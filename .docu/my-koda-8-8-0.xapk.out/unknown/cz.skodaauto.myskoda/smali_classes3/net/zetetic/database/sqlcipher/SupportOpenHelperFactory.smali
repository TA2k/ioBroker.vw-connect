.class public Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/sqlite/db/a;


# static fields
.field private static final UNCHANGED:I = -0x1


# instance fields
.field private final enableWriteAheadLogging:Z

.field private final hook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

.field private final minimumSupportedVersion:I

.field private final password:[B


# direct methods
.method public constructor <init>([B)V
    .locals 2

    const/4 v0, 0x0

    const/4 v1, 0x0

    .line 1
    invoke-direct {p0, p1, v0, v1}, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;-><init>([BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V

    return-void
.end method

.method public constructor <init>([BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V
    .locals 1

    const/4 v0, -0x1

    .line 2
    invoke-direct {p0, p1, p2, p3, v0}, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;-><init>([BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZI)V

    return-void
.end method

.method public constructor <init>([BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZI)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->password:[B

    .line 5
    iput-object p2, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->hook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 6
    iput-boolean p3, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->enableWriteAheadLogging:Z

    .line 7
    iput p4, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->minimumSupportedVersion:I

    return-void
.end method


# virtual methods
.method public create(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;)Landroidx/sqlite/db/SupportSQLiteOpenHelper;
    .locals 6

    .line 1
    iget v5, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->minimumSupportedVersion:I

    .line 2
    .line 3
    const/4 v0, -0x1

    .line 4
    if-ne v5, v0, :cond_0

    .line 5
    .line 6
    new-instance v0, Lnet/zetetic/database/sqlcipher/SupportHelper;

    .line 7
    .line 8
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->password:[B

    .line 9
    .line 10
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->hook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 11
    .line 12
    iget-boolean p0, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->enableWriteAheadLogging:Z

    .line 13
    .line 14
    invoke-direct {v0, p1, v1, v2, p0}, Lnet/zetetic/database/sqlcipher/SupportHelper;-><init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V

    .line 15
    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SupportHelper;

    .line 19
    .line 20
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->password:[B

    .line 21
    .line 22
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->hook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 23
    .line 24
    iget-boolean v4, p0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;->enableWriteAheadLogging:Z

    .line 25
    .line 26
    move-object v1, p1

    .line 27
    invoke-direct/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SupportHelper;-><init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZI)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

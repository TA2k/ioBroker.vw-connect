.class Lnet/zetetic/database/sqlcipher/SupportHelper$1;
.super Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lnet/zetetic/database/sqlcipher/SupportHelper;-><init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZI)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lnet/zetetic/database/sqlcipher/SupportHelper;

.field final synthetic val$configuration:Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SupportHelper;Landroid/content/Context;Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;ZLandroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;->this$0:Lnet/zetetic/database/sqlcipher/SupportHelper;

    .line 2
    .line 3
    iput-object p11, p0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;->val$configuration:Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    .line 4
    .line 5
    move-object p1, p2

    .line 6
    move-object p2, p3

    .line 7
    move-object p3, p4

    .line 8
    move-object p4, p5

    .line 9
    move p5, p6

    .line 10
    move p6, p7

    .line 11
    move-object p7, p8

    .line 12
    move-object p8, p9

    .line 13
    move p9, p10

    .line 14
    invoke-direct/range {p0 .. p9}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public onConfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;->val$configuration:Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->c:Lb11/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const-string p0, "db"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public onCreate(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;->val$configuration:Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->c:Lb11/a;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lb11/a;->e(Landroidx/sqlite/db/SupportSQLiteDatabase;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public onDowngrade(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;->val$configuration:Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->c:Lb11/a;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Lb11/a;->f(Landroidx/sqlite/db/SupportSQLiteDatabase;II)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public onOpen(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;->val$configuration:Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->c:Lb11/a;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lb11/a;->g(Landroidx/sqlite/db/SupportSQLiteDatabase;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public onUpgrade(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SupportHelper$1;->val$configuration:Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->c:Lb11/a;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Lb11/a;->h(Landroidx/sqlite/db/SupportSQLiteDatabase;II)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

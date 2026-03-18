.class public final synthetic Lqe0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroid/database/sqlite/SQLiteException;


# direct methods
.method public synthetic constructor <init>(Landroid/database/sqlite/SQLiteException;I)V
    .locals 0

    .line 1
    iput p2, p0, Lqe0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqe0/e;->e:Landroid/database/sqlite/SQLiteException;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lqe0/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lne0/c;

    .line 7
    .line 8
    new-instance v2, Ljava/security/GeneralSecurityException;

    .line 9
    .line 10
    const-string v0, "Corrupted database - database is deleted"

    .line 11
    .line 12
    iget-object p0, p0, Lqe0/e;->e:Landroid/database/sqlite/SQLiteException;

    .line 13
    .line 14
    invoke-direct {v2, v0, p0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 15
    .line 16
    .line 17
    const/4 v5, 0x0

    .line 18
    const/16 v6, 0x1e

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 23
    .line 24
    .line 25
    return-object v1

    .line 26
    :pswitch_0
    new-instance v2, Lne0/c;

    .line 27
    .line 28
    const/4 v6, 0x0

    .line 29
    const/16 v7, 0x1e

    .line 30
    .line 31
    iget-object v3, p0, Lqe0/e;->e:Landroid/database/sqlite/SQLiteException;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    const/4 v5, 0x0

    .line 35
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 36
    .line 37
    .line 38
    return-object v2

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

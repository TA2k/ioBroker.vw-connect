.class public final Lwa/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/sqlite/db/SupportSQLiteOpenHelper;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Ljava/lang/String;

.field public final f:Lb11/a;

.field public final g:Z

.field public final h:Z

.field public final i:Llx0/q;

.field public j:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lb11/a;ZZ)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "callback"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lwa/g;->d:Landroid/content/Context;

    .line 15
    .line 16
    iput-object p2, p0, Lwa/g;->e:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p3, p0, Lwa/g;->f:Lb11/a;

    .line 19
    .line 20
    iput-boolean p4, p0, Lwa/g;->g:Z

    .line 21
    .line 22
    iput-boolean p5, p0, Lwa/g;->h:Z

    .line 23
    .line 24
    new-instance p1, Lu2/a;

    .line 25
    .line 26
    const/16 p2, 0x12

    .line 27
    .line 28
    invoke-direct {p1, p0, p2}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lwa/g;->i:Llx0/q;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 1

    .line 1
    iget-object p0, p0, Lwa/g;->i:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->isInitialized()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lwa/f;

    .line 14
    .line 15
    invoke-virtual {p0}, Lwa/f;->close()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final getDatabaseName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWritableDatabase()Landroidx/sqlite/db/SupportSQLiteDatabase;
    .locals 1

    .line 1
    iget-object p0, p0, Lwa/g;->i:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lwa/f;

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    invoke-virtual {p0, v0}, Lwa/f;->a(Z)Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final setWriteAheadLoggingEnabled(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lwa/g;->i:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->isInitialized()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lwa/f;

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Landroid/database/sqlite/SQLiteOpenHelper;->setWriteAheadLoggingEnabled(Z)V

    .line 16
    .line 17
    .line 18
    :cond_0
    iput-boolean p1, p0, Lwa/g;->j:Z

    .line 19
    .line 20
    return-void
.end method

.class public final Lop/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lop/b;


# static fields
.field public static final g:Lfv/b;


# instance fields
.field public final d:Lop/d;

.field public volatile e:Lop/b;

.field public f:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfv/b;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lop/c;->g:Lfv/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lcq/r1;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lop/d;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lop/c;->d:Lop/d;

    .line 10
    .line 11
    iput-object p1, p0, Lop/c;->e:Lop/b;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final h()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lop/c;->e:Lop/b;

    .line 2
    .line 3
    sget-object v1, Lop/c;->g:Lfv/b;

    .line 4
    .line 5
    if-eq v0, v1, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Lop/c;->d:Lop/d;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    :try_start_0
    iget-object v2, p0, Lop/c;->e:Lop/b;

    .line 11
    .line 12
    if-eq v2, v1, :cond_0

    .line 13
    .line 14
    iget-object v2, p0, Lop/c;->e:Lop/b;

    .line 15
    .line 16
    invoke-interface {v2}, Lop/b;->h()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    iput-object v2, p0, Lop/c;->f:Ljava/lang/Object;

    .line 21
    .line 22
    iput-object v1, p0, Lop/c;->e:Lop/b;

    .line 23
    .line 24
    monitor-exit v0

    .line 25
    return-object v2

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    monitor-exit v0

    .line 29
    goto :goto_1

    .line 30
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    throw p0

    .line 32
    :cond_1
    :goto_1
    iget-object p0, p0, Lop/c;->f:Ljava/lang/Object;

    .line 33
    .line 34
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lop/c;->e:Lop/b;

    .line 2
    .line 3
    sget-object v1, Lop/c;->g:Lfv/b;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lop/c;->f:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string v0, "<supplier that returned "

    .line 14
    .line 15
    const-string v1, ">"

    .line 16
    .line 17
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    :cond_0
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v0, "Suppliers.memoize("

    .line 26
    .line 27
    const-string v1, ")"

    .line 28
    .line 29
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

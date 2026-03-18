.class public final Laq/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Laq/t;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Laq/t;

    invoke-direct {v0}, Laq/t;-><init>()V

    iput-object v0, p0, Laq/k;->a:Laq/t;

    return-void
.end method

.method public constructor <init>(La0/j;)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Laq/t;

    invoke-direct {v0}, Laq/t;-><init>()V

    iput-object v0, p0, Laq/k;->a:Laq/t;

    new-instance v0, Laq/s;

    invoke-direct {v0, p0}, Laq/s;-><init>(Laq/k;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3
    new-instance p0, La0/j;

    const/4 v1, 0x2

    invoke-direct {p0, v0, v1}, La0/j;-><init>(Ljava/lang/Object;I)V

    iget-object p1, p1, La0/j;->e:Ljava/lang/Object;

    check-cast p1, Laq/t;

    sget-object v0, Laq/l;->a:Lj0/e;

    invoke-virtual {p1, v0, p0}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/k;->a:Laq/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/k;->a:Laq/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/t;->o(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(Ljava/lang/Exception;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Laq/k;->a:Laq/t;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string v0, "Exception must not be null"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter v0

    .line 14
    :try_start_0
    iget-boolean v1, p0, Laq/t;->c:Z

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    monitor-exit v0

    .line 19
    const/4 p0, 0x0

    .line 20
    return p0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v1, 0x1

    .line 24
    iput-boolean v1, p0, Laq/t;->c:Z

    .line 25
    .line 26
    iput-object p1, p0, Laq/t;->f:Ljava/lang/Exception;

    .line 27
    .line 28
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 30
    .line 31
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/measurement/i4;->C(Laq/j;)V

    .line 32
    .line 33
    .line 34
    return v1

    .line 35
    :goto_0
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    throw p0
.end method

.method public final d(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/k;->a:Laq/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/t;->q(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

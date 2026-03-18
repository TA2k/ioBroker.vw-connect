.class public final Lbp/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lfs/f;

.field public final b:Laq/k;

.field public final synthetic c:Lbp/u;


# direct methods
.method public constructor <init>(Lbp/u;Lfs/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbp/t;->c:Lbp/u;

    .line 5
    .line 6
    new-instance p1, Laq/k;

    .line 7
    .line 8
    invoke-direct {p1}, Laq/k;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lbp/t;->b:Laq/k;

    .line 12
    .line 13
    iput-object p2, p0, Lbp/t;->a:Lfs/f;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    iget-object v0, p0, Lbp/t;->c:Lbp/u;

    .line 2
    .line 3
    iget-object v0, v0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Lbp/t;->c:Lbp/u;

    .line 7
    .line 8
    iget v1, v1, Lbp/u;->g:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    move v1, v2

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v1, 0x0

    .line 16
    :goto_0
    invoke-static {v1}, Lno/c0;->k(Z)V

    .line 17
    .line 18
    .line 19
    iget-object v1, p0, Lbp/t;->c:Lbp/u;

    .line 20
    .line 21
    iput v2, v1, Lbp/u;->g:I

    .line 22
    .line 23
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    iget-object v0, v1, Lbp/u;->d:Lbp/q;

    .line 25
    .line 26
    new-instance v1, Lbp/s;

    .line 27
    .line 28
    invoke-direct {v1, p0}, Lbp/s;-><init>(Lbp/t;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v2, v1}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iget-object v1, p0, Lbp/t;->c:Lbp/u;

    .line 36
    .line 37
    new-instance v2, Laq/a;

    .line 38
    .line 39
    const/4 v3, 0x6

    .line 40
    invoke-direct {v2, p0, v3}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v1, v2}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :catchall_0
    move-exception p0

    .line 48
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 49
    throw p0
.end method

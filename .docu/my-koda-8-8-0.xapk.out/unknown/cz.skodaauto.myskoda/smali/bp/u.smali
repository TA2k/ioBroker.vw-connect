.class public final Lbp/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/e;
.implements Ljava/util/concurrent/Executor;


# instance fields
.field public final d:Lbp/q;

.field public final e:Lbp/c;

.field public final f:Ljava/util/ArrayDeque;

.field public g:I


# direct methods
.method public constructor <init>(Lbp/q;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayDeque;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput v0, p0, Lbp/u;->g:I

    .line 13
    .line 14
    iput-object p1, p0, Lbp/u;->d:Lbp/q;

    .line 15
    .line 16
    new-instance v0, Lbp/c;

    .line 17
    .line 18
    iget-object p1, p1, Lko/i;->i:Landroid/os/Looper;

    .line 19
    .line 20
    invoke-direct {v0, p1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lbp/u;->e:Lbp/c;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Lfs/f;)Laq/t;
    .locals 3

    .line 1
    new-instance v0, Lbp/t;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lbp/t;-><init>(Lbp/u;Lfs/f;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, v0, Lbp/t;->b:Laq/k;

    .line 7
    .line 8
    iget-object p1, p1, Laq/k;->a:Laq/t;

    .line 9
    .line 10
    invoke-virtual {p1, p0, p0}, Laq/t;->b(Ljava/util/concurrent/Executor;Laq/e;)Laq/t;

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 14
    .line 15
    monitor-enter v1

    .line 16
    :try_start_0
    iget-object v2, p0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    iget-object p0, p0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    invoke-virtual {v0}, Lbp/t;->a()V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-object p1

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    throw p0
.end method

.method public final execute(Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lbp/u;->e:Lbp/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onComplete(Laq/j;)V
    .locals 3

    .line 1
    iget-object p1, p0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget v0, p0, Lbp/u;->g:I

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    const/4 v2, 0x0

    .line 8
    if-ne v0, v1, :cond_1

    .line 9
    .line 10
    iget-object v0, p0, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lbp/t;

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v1, v2

    .line 23
    :goto_0
    invoke-static {v1}, Lno/c0;->k(Z)V

    .line 24
    .line 25
    .line 26
    goto :goto_1

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    goto :goto_2

    .line 29
    :cond_1
    const/4 v0, 0x0

    .line 30
    :goto_1
    iput v2, p0, Lbp/u;->g:I

    .line 31
    .line 32
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    if-eqz v0, :cond_2

    .line 34
    .line 35
    invoke-virtual {v0}, Lbp/t;->a()V

    .line 36
    .line 37
    .line 38
    :cond_2
    return-void

    .line 39
    :goto_2
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 40
    throw p0
.end method

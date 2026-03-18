.class public final Laq/t;
.super Laq/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Lcom/google/android/gms/internal/measurement/i4;

.field public c:Z

.field public volatile d:Z

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Exception;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/gms/internal/measurement/i4;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/i4;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/concurrent/Executor;Laq/d;)Laq/t;
    .locals 1

    .line 1
    new-instance v0, Laq/q;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/d;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Laq/t;->s()V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final b(Ljava/util/concurrent/Executor;Laq/e;)Laq/t;
    .locals 1

    .line 1
    new-instance v0, Laq/q;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/e;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Laq/t;->s()V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;
    .locals 1

    .line 1
    new-instance v0, Laq/q;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/f;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Laq/t;->s()V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;
    .locals 1

    .line 1
    new-instance v0, Laq/q;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/g;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Laq/t;->s()V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;
    .locals 3

    .line 1
    new-instance v0, Laq/t;

    .line 2
    .line 3
    invoke-direct {v0}, Laq/t;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Laq/o;

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-direct {v1, p1, p2, v0, v2}, Laq/o;-><init>(Ljava/util/concurrent/Executor;Laq/b;Laq/t;I)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 13
    .line 14
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Laq/t;->s()V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method public final f()Ljava/lang/Exception;
    .locals 1

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Laq/t;->f:Ljava/lang/Exception;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-object p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public final g()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Laq/t;->c:Z

    .line 5
    .line 6
    const-string v2, "Task is not yet complete"

    .line 7
    .line 8
    invoke-static {v2, v1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 9
    .line 10
    .line 11
    iget-boolean v1, p0, Laq/t;->d:Z

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    iget-object v1, p0, Laq/t;->f:Ljava/lang/Exception;

    .line 16
    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, Laq/t;->e:Ljava/lang/Object;

    .line 20
    .line 21
    monitor-exit v0

    .line 22
    return-object p0

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Laq/h;

    .line 26
    .line 27
    invoke-direct {p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 32
    .line 33
    const-string v1, "Task is already canceled."

    .line 34
    .line 35
    invoke-direct {p0, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    throw p0
.end method

.method public final h()Z
    .locals 1

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean p0, p0, Laq/t;->c:Z

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public final i()Z
    .locals 3

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Laq/t;->c:Z

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget-boolean v1, p0, Laq/t;->d:Z

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Laq/t;->f:Ljava/lang/Exception;

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    goto :goto_0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    :goto_0
    monitor-exit v0

    .line 22
    return v2

    .line 23
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    throw p0
.end method

.method public final j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;
    .locals 2

    .line 1
    new-instance v0, Laq/t;

    .line 2
    .line 3
    invoke-direct {v0}, Laq/t;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Laq/q;

    .line 7
    .line 8
    invoke-direct {v1, p1, p2, v0}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/i;Laq/t;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 12
    .line 13
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Laq/t;->s()V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public final k(Laq/e;)Laq/t;
    .locals 2

    .line 1
    sget-object v0, Laq/l;->a:Lj0/e;

    .line 2
    .line 3
    new-instance v1, Laq/q;

    .line 4
    .line 5
    invoke-direct {v1, v0, p1}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/e;)V

    .line 6
    .line 7
    .line 8
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 9
    .line 10
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Laq/t;->s()V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public final l(Laq/f;)Laq/t;
    .locals 1

    .line 1
    sget-object v0, Laq/l;->a:Lj0/e;

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;
    .locals 3

    .line 1
    new-instance v0, Laq/t;

    .line 2
    .line 3
    invoke-direct {v0}, Laq/t;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Laq/o;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, p1, p2, v0, v2}, Laq/o;-><init>(Ljava/util/concurrent/Executor;Laq/b;Laq/t;I)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 13
    .line 14
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Laq/t;->s()V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method public final n(Ljava/lang/Exception;)V
    .locals 2

    .line 1
    const-string v0, "Exception must not be null"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    invoke-virtual {p0}, Laq/t;->r()V

    .line 10
    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    iput-boolean v1, p0, Laq/t;->c:Z

    .line 14
    .line 15
    iput-object p1, p0, Laq/t;->f:Ljava/lang/Exception;

    .line 16
    .line 17
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 19
    .line 20
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/measurement/i4;->C(Laq/j;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    throw p0
.end method

.method public final o(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Laq/t;->r()V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iput-boolean v1, p0, Laq/t;->c:Z

    .line 9
    .line 10
    iput-object p1, p0, Laq/t;->e:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 14
    .line 15
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/measurement/i4;->C(Laq/j;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    throw p0
.end method

.method public final p()V
    .locals 2

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Laq/t;->c:Z

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v1, 0x1

    .line 13
    iput-boolean v1, p0, Laq/t;->c:Z

    .line 14
    .line 15
    iput-boolean v1, p0, Laq/t;->d:Z

    .line 16
    .line 17
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    iget-object v0, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Lcom/google/android/gms/internal/measurement/i4;->C(Laq/j;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :goto_0
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    throw p0
.end method

.method public final q(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Laq/t;->c:Z

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v1, 0x1

    .line 14
    iput-boolean v1, p0, Laq/t;->c:Z

    .line 15
    .line 16
    iput-object p1, p0, Laq/t;->e:Ljava/lang/Object;

    .line 17
    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    iget-object p1, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/measurement/i4;->C(Laq/j;)V

    .line 22
    .line 23
    .line 24
    return v1

    .line 25
    :goto_0
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    throw p0
.end method

.method public final r()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Laq/t;->c:Z

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    sget v0, Laq/c;->e:I

    .line 6
    .line 7
    invoke-virtual {p0}, Laq/t;->h()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_3

    .line 12
    .line 13
    invoke-virtual {p0}, Laq/t;->f()Ljava/lang/Exception;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-nez v0, :cond_2

    .line 18
    .line 19
    invoke-virtual {p0}, Laq/t;->i()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-nez v1, :cond_1

    .line 24
    .line 25
    iget-boolean p0, p0, Laq/t;->d:Z

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    const-string p0, "cancellation"

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const-string p0, "unknown issue"

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-virtual {p0}, Laq/t;->g()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    const-string v1, "result "

    .line 44
    .line 45
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    goto :goto_0

    .line 50
    :cond_2
    const-string p0, "failure"

    .line 51
    .line 52
    :goto_0
    new-instance v1, Laq/c;

    .line 53
    .line 54
    const-string v2, "Complete with: "

    .line 55
    .line 56
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    const/4 v2, 0x0

    .line 61
    invoke-direct {v1, v2, p0, v0}, Laq/c;-><init>(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string p0, "DuplicateTaskCompletionException can only be created from completed Task."

    .line 68
    .line 69
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    :goto_1
    throw v1

    .line 73
    :cond_4
    return-void
.end method

.method public final s()V
    .locals 2

    .line 1
    iget-object v0, p0, Laq/t;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Laq/t;->c:Z

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    iget-object v0, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Lcom/google/android/gms/internal/measurement/i4;->C(Laq/j;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :goto_0
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    throw p0
.end method

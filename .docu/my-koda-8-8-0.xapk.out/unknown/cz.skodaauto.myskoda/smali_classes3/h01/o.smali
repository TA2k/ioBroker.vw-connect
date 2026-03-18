.class public final Lh01/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/j;
.implements Ljava/lang/Cloneable;


# instance fields
.field public final d:Ld01/h0;

.field public final e:Ld01/k0;

.field public final f:Z

.field public final g:Lh01/q;

.field public final h:Lh01/n;

.field public final i:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public j:Ljava/lang/Object;

.field public k:Lh01/h;

.field public l:Lh01/p;

.field public m:Z

.field public n:Lh01/g;

.field public o:Z

.field public p:Z

.field public q:Z

.field public r:Z

.field public s:Z

.field public volatile t:Z

.field public volatile u:Lh01/g;

.field public final v:Ljava/util/concurrent/CopyOnWriteArrayList;


# direct methods
.method public constructor <init>(Ld01/h0;Ld01/k0;Z)V
    .locals 2

    .line 1
    const-string v0, "originalRequest"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lh01/o;->d:Ld01/h0;

    .line 10
    .line 11
    iput-object p2, p0, Lh01/o;->e:Ld01/k0;

    .line 12
    .line 13
    iput-boolean p3, p0, Lh01/o;->f:Z

    .line 14
    .line 15
    iget-object p3, p1, Ld01/h0;->E:Lbu/c;

    .line 16
    .line 17
    iget-object p3, p3, Lbu/c;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p3, Lh01/q;

    .line 20
    .line 21
    iput-object p3, p0, Lh01/o;->g:Lh01/q;

    .line 22
    .line 23
    iget-object p3, p1, Ld01/h0;->d:Lc1/y;

    .line 24
    .line 25
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    new-instance p3, Lh01/n;

    .line 29
    .line 30
    invoke-direct {p3, p0}, Lh01/n;-><init>(Lh01/o;)V

    .line 31
    .line 32
    .line 33
    iget p1, p1, Ld01/h0;->w:I

    .line 34
    .line 35
    int-to-long v0, p1

    .line 36
    sget-object p1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 37
    .line 38
    invoke-virtual {p3, v0, v1, p1}, Lu01/j0;->g(JLjava/util/concurrent/TimeUnit;)Lu01/j0;

    .line 39
    .line 40
    .line 41
    iput-object p3, p0, Lh01/o;->h:Lh01/n;

    .line 42
    .line 43
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 44
    .line 45
    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lh01/o;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 49
    .line 50
    const/4 p1, 0x1

    .line 51
    iput-boolean p1, p0, Lh01/o;->s:Z

    .line 52
    .line 53
    new-instance p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 54
    .line 55
    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 56
    .line 57
    .line 58
    iput-object p1, p0, Lh01/o;->v:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 59
    .line 60
    new-instance p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 61
    .line 62
    iget-object p1, p2, Ld01/k0;->e:Ljp/ng;

    .line 63
    .line 64
    invoke-direct {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public static final a(Lh01/o;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-boolean v1, p0, Lh01/o;->t:Z

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    const-string v1, "canceled "

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string v1, ""

    .line 14
    .line 15
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lh01/o;->f:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    const-string v1, "web socket"

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    const-string v1, "call"

    .line 26
    .line 27
    :goto_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, " to "

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lh01/o;->e:Ld01/k0;

    .line 36
    .line 37
    iget-object p0, p0, Ld01/k0;->a:Ld01/a0;

    .line 38
    .line 39
    invoke-virtual {p0}, Ld01/a0;->i()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method


# virtual methods
.method public final b(Lh01/p;)V
    .locals 2

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 7
    .line 8
    iget-object v0, p0, Lh01/o;->l:Lh01/p;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iput-object p1, p0, Lh01/o;->l:Lh01/p;

    .line 13
    .line 14
    iget-object p1, p1, Lh01/p;->p:Ljava/util/ArrayList;

    .line 15
    .line 16
    new-instance v0, Lh01/m;

    .line 17
    .line 18
    iget-object v1, p0, Lh01/o;->j:Ljava/lang/Object;

    .line 19
    .line 20
    invoke-direct {v0, p0, v1}, Lh01/m;-><init>(Lh01/o;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "Check failed."

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public final c(Ljava/io/IOException;)Ljava/io/IOException;
    .locals 2

    .line 1
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 2
    .line 3
    iget-object v0, p0, Lh01/o;->l:Lh01/p;

    .line 4
    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    invoke-virtual {p0}, Lh01/o;->i()Ljava/net/Socket;

    .line 9
    .line 10
    .line 11
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    monitor-exit v0

    .line 13
    iget-object v0, p0, Lh01/o;->l:Lh01/p;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    if-eqz v1, :cond_2

    .line 18
    .line 19
    invoke-static {v1}, Le01/g;->c(Ljava/net/Socket;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    if-nez v1, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "Check failed."

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    monitor-exit v0

    .line 36
    throw p0

    .line 37
    :cond_2
    :goto_0
    iget-boolean v0, p0, Lh01/o;->m:Z

    .line 38
    .line 39
    if-eqz v0, :cond_3

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_3
    iget-object p0, p0, Lh01/o;->h:Lh01/n;

    .line 43
    .line 44
    invoke-virtual {p0}, Lu01/d;->i()Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-nez p0, :cond_4

    .line 49
    .line 50
    :goto_1
    move-object p0, p1

    .line 51
    goto :goto_2

    .line 52
    :cond_4
    new-instance p0, Ljava/io/InterruptedIOException;

    .line 53
    .line 54
    const-string v0, "timeout"

    .line 55
    .line 56
    invoke-direct {p0, v0}, Ljava/io/InterruptedIOException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    if-eqz p1, :cond_5

    .line 60
    .line 61
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 62
    .line 63
    .line 64
    :cond_5
    :goto_2
    if-eqz p1, :cond_6

    .line 65
    .line 66
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    :cond_6
    return-object p0
.end method

.method public final cancel()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh01/o;->t:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lh01/o;->t:Z

    .line 8
    .line 9
    iget-object v0, p0, Lh01/o;->u:Lh01/g;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object v0, v0, Lh01/g;->c:Li01/d;

    .line 14
    .line 15
    invoke-interface {v0}, Li01/d;->cancel()V

    .line 16
    .line 17
    .line 18
    :cond_1
    iget-object p0, p0, Lh01/o;->v:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const-string v0, "iterator(...)"

    .line 25
    .line 26
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_2

    .line 34
    .line 35
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lh01/u;

    .line 40
    .line 41
    invoke-interface {v0}, Lh01/u;->cancel()V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    return-void
.end method

.method public final clone()Ld01/j;
    .locals 3

    .line 2
    new-instance v0, Lh01/o;

    iget-object v1, p0, Lh01/o;->e:Ld01/k0;

    iget-boolean v2, p0, Lh01/o;->f:Z

    iget-object p0, p0, Lh01/o;->d:Ld01/h0;

    invoke-direct {v0, p0, v1, v2}, Lh01/o;-><init>(Ld01/h0;Ld01/k0;Z)V

    return-object v0
.end method

.method public final bridge synthetic clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh01/o;->clone()Ld01/j;

    move-result-object p0

    return-object p0
.end method

.method public final d(Z)V
    .locals 8

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lh01/o;->s:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object v2, p0, Lh01/o;->u:Lh01/g;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    iget-object p1, v2, Lh01/g;->c:Li01/d;

    .line 14
    .line 15
    invoke-interface {p1}, Li01/d;->cancel()V

    .line 16
    .line 17
    .line 18
    iget-object v1, v2, Lh01/g;->a:Lh01/o;

    .line 19
    .line 20
    const/4 v6, 0x1

    .line 21
    const/4 v7, 0x0

    .line 22
    const/4 v3, 0x1

    .line 23
    const/4 v4, 0x1

    .line 24
    const/4 v5, 0x1

    .line 25
    invoke-virtual/range {v1 .. v7}, Lh01/o;->f(Lh01/g;ZZZZLjava/io/IOException;)Ljava/io/IOException;

    .line 26
    .line 27
    .line 28
    :cond_0
    const/4 p1, 0x0

    .line 29
    iput-object p1, p0, Lh01/o;->n:Lh01/g;

    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    :try_start_1
    const-string p1, "released"

    .line 33
    .line 34
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    move-object p1, v0

    .line 42
    monitor-exit p0

    .line 43
    throw p1
.end method

.method public final e()Ld01/t0;
    .locals 9

    .line 1
    new-instance v2, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh01/o;->d:Ld01/h0;

    .line 7
    .line 8
    iget-object v0, v0, Ld01/h0;->b:Ljava/util/List;

    .line 9
    .line 10
    check-cast v0, Ljava/lang/Iterable;

    .line 11
    .line 12
    invoke-static {v0, v2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Lfl/b;

    .line 16
    .line 17
    iget-object v1, p0, Lh01/o;->d:Ld01/h0;

    .line 18
    .line 19
    const/4 v3, 0x2

    .line 20
    invoke-direct {v0, v1, v3}, Lfl/b;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    new-instance v0, Ldm0/i;

    .line 27
    .line 28
    iget-object v1, p0, Lh01/o;->d:Ld01/h0;

    .line 29
    .line 30
    iget-object v1, v1, Ld01/h0;->j:Ld01/r;

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ldm0/i;-><init>(Ld01/r;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    new-instance v0, Ldm0/i;

    .line 39
    .line 40
    iget-object v1, p0, Lh01/o;->d:Ld01/h0;

    .line 41
    .line 42
    iget-object v1, v1, Ld01/h0;->k:Ld01/g;

    .line 43
    .line 44
    const/4 v3, 0x1

    .line 45
    invoke-direct {v0, v1, v3}, Ldm0/i;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    sget-object v0, Lh01/a;->a:Lh01/a;

    .line 52
    .line 53
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    iget-boolean v0, p0, Lh01/o;->f:Z

    .line 57
    .line 58
    if-nez v0, :cond_0

    .line 59
    .line 60
    iget-object v0, p0, Lh01/o;->d:Ld01/h0;

    .line 61
    .line 62
    iget-object v0, v0, Ld01/h0;->c:Ljava/util/List;

    .line 63
    .line 64
    check-cast v0, Ljava/lang/Iterable;

    .line 65
    .line 66
    invoke-static {v0, v2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 67
    .line 68
    .line 69
    :cond_0
    sget-object v0, Li01/a;->a:Li01/a;

    .line 70
    .line 71
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    new-instance v0, Li01/f;

    .line 75
    .line 76
    iget-object v5, p0, Lh01/o;->e:Ld01/k0;

    .line 77
    .line 78
    iget-object v1, p0, Lh01/o;->d:Ld01/h0;

    .line 79
    .line 80
    iget v6, v1, Ld01/h0;->x:I

    .line 81
    .line 82
    iget v7, v1, Ld01/h0;->y:I

    .line 83
    .line 84
    iget v8, v1, Ld01/h0;->z:I

    .line 85
    .line 86
    const/4 v3, 0x0

    .line 87
    const/4 v4, 0x0

    .line 88
    move-object v1, p0

    .line 89
    invoke-direct/range {v0 .. v8}, Li01/f;-><init>(Lh01/o;Ljava/util/ArrayList;ILh01/g;Ld01/k0;III)V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x0

    .line 93
    const/4 v2, 0x0

    .line 94
    :try_start_0
    iget-object v3, v1, Lh01/o;->e:Ld01/k0;

    .line 95
    .line 96
    invoke-virtual {v0, v3}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iget-boolean v3, v1, Lh01/o;->t:Z
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 101
    .line 102
    if-nez v3, :cond_1

    .line 103
    .line 104
    invoke-virtual {v1, p0}, Lh01/o;->h(Ljava/io/IOException;)Ljava/io/IOException;

    .line 105
    .line 106
    .line 107
    return-object v0

    .line 108
    :cond_1
    :try_start_1
    invoke-static {v0}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 109
    .line 110
    .line 111
    new-instance v0, Ljava/io/IOException;

    .line 112
    .line 113
    const-string v3, "Canceled"

    .line 114
    .line 115
    invoke-direct {v0, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw v0
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 119
    :catchall_0
    move-exception v0

    .line 120
    goto :goto_0

    .line 121
    :catch_0
    move-exception v0

    .line 122
    const/4 v2, 0x1

    .line 123
    :try_start_2
    invoke-virtual {v1, v0}, Lh01/o;->h(Ljava/io/IOException;)Ljava/io/IOException;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    const-string v3, "null cannot be cast to non-null type kotlin.Throwable"

    .line 128
    .line 129
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 133
    :goto_0
    if-nez v2, :cond_2

    .line 134
    .line 135
    invoke-virtual {v1, p0}, Lh01/o;->h(Ljava/io/IOException;)Ljava/io/IOException;

    .line 136
    .line 137
    .line 138
    :cond_2
    throw v0
.end method

.method public final enqueue(Ld01/k;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lh01/o;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 12
    .line 13
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 14
    .line 15
    invoke-virtual {v0}, Ln01/b;->b()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iput-object v0, p0, Lh01/o;->j:Ljava/lang/Object;

    .line 20
    .line 21
    iget-object v0, p0, Lh01/o;->d:Ld01/h0;

    .line 22
    .line 23
    iget-object v0, v0, Ld01/h0;->a:Ld01/t;

    .line 24
    .line 25
    new-instance v1, Lh01/l;

    .line 26
    .line 27
    invoke-direct {v1, p0, p1}, Lh01/l;-><init>(Lh01/o;Ld01/k;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    const/4 p0, 0x6

    .line 34
    const/4 p1, 0x0

    .line 35
    invoke-static {v0, v1, p1, p1, p0}, Ld01/t;->d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 40
    .line 41
    const-string p1, "Already Executed"

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0
.end method

.method public final execute()Ld01/t0;
    .locals 4

    .line 1
    iget-object v0, p0, Lh01/o;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lh01/o;->h:Lh01/n;

    .line 12
    .line 13
    invoke-virtual {v0}, Lu01/d;->h()V

    .line 14
    .line 15
    .line 16
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 17
    .line 18
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 19
    .line 20
    invoke-virtual {v0}, Ln01/b;->b()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Lh01/o;->j:Ljava/lang/Object;

    .line 25
    .line 26
    const/4 v0, 0x5

    .line 27
    const/4 v1, 0x0

    .line 28
    :try_start_0
    iget-object v2, p0, Lh01/o;->d:Ld01/h0;

    .line 29
    .line 30
    iget-object v2, v2, Ld01/h0;->a:Ld01/t;

    .line 31
    .line 32
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    :try_start_1
    iget-object v3, v2, Ld01/t;->d:Ljava/util/ArrayDeque;

    .line 34
    .line 35
    invoke-virtual {v3, p0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 36
    .line 37
    .line 38
    :try_start_2
    monitor-exit v2

    .line 39
    invoke-virtual {p0}, Lh01/o;->e()Ld01/t0;

    .line 40
    .line 41
    .line 42
    move-result-object v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 43
    iget-object v3, p0, Lh01/o;->d:Ld01/h0;

    .line 44
    .line 45
    iget-object v3, v3, Ld01/h0;->a:Ld01/t;

    .line 46
    .line 47
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    invoke-static {v3, v1, p0, v1, v0}, Ld01/t;->d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V

    .line 51
    .line 52
    .line 53
    return-object v2

    .line 54
    :catchall_0
    move-exception v2

    .line 55
    goto :goto_0

    .line 56
    :catchall_1
    move-exception v3

    .line 57
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 58
    :try_start_4
    throw v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 59
    :goto_0
    iget-object v3, p0, Lh01/o;->d:Ld01/h0;

    .line 60
    .line 61
    iget-object v3, v3, Ld01/h0;->a:Ld01/t;

    .line 62
    .line 63
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    invoke-static {v3, v1, p0, v1, v0}, Ld01/t;->d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V

    .line 67
    .line 68
    .line 69
    throw v2

    .line 70
    :cond_0
    const-string p0, "Already Executed"

    .line 71
    .line 72
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0
.end method

.method public final f(Lh01/g;ZZZZLjava/io/IOException;)Ljava/io/IOException;
    .locals 3

    .line 1
    const-string v0, "exchange"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh01/o;->u:Lh01/g;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-nez p1, :cond_0

    .line 13
    .line 14
    goto/16 :goto_5

    .line 15
    .line 16
    :cond_0
    monitor-enter p0

    .line 17
    const/4 p1, 0x1

    .line 18
    const/4 v0, 0x0

    .line 19
    if-eqz p2, :cond_1

    .line 20
    .line 21
    :try_start_0
    iget-boolean v1, p0, Lh01/o;->o:Z

    .line 22
    .line 23
    if-nez v1, :cond_4

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception p1

    .line 27
    goto :goto_2

    .line 28
    :cond_1
    :goto_0
    if-eqz p3, :cond_2

    .line 29
    .line 30
    iget-boolean v1, p0, Lh01/o;->p:Z

    .line 31
    .line 32
    if-nez v1, :cond_4

    .line 33
    .line 34
    :cond_2
    if-eqz p5, :cond_3

    .line 35
    .line 36
    iget-boolean v1, p0, Lh01/o;->q:Z

    .line 37
    .line 38
    if-nez v1, :cond_4

    .line 39
    .line 40
    :cond_3
    if-eqz p4, :cond_b

    .line 41
    .line 42
    iget-boolean v1, p0, Lh01/o;->r:Z

    .line 43
    .line 44
    if-eqz v1, :cond_b

    .line 45
    .line 46
    :cond_4
    if-eqz p2, :cond_5

    .line 47
    .line 48
    iput-boolean v0, p0, Lh01/o;->o:Z

    .line 49
    .line 50
    :cond_5
    if-eqz p3, :cond_6

    .line 51
    .line 52
    iput-boolean v0, p0, Lh01/o;->p:Z

    .line 53
    .line 54
    :cond_6
    if-eqz p5, :cond_7

    .line 55
    .line 56
    iput-boolean v0, p0, Lh01/o;->q:Z

    .line 57
    .line 58
    :cond_7
    if-eqz p4, :cond_8

    .line 59
    .line 60
    iput-boolean v0, p0, Lh01/o;->r:Z

    .line 61
    .line 62
    :cond_8
    iget-boolean p2, p0, Lh01/o;->o:Z

    .line 63
    .line 64
    if-nez p2, :cond_9

    .line 65
    .line 66
    iget-boolean p2, p0, Lh01/o;->p:Z

    .line 67
    .line 68
    if-nez p2, :cond_9

    .line 69
    .line 70
    iget-boolean p2, p0, Lh01/o;->q:Z

    .line 71
    .line 72
    if-nez p2, :cond_9

    .line 73
    .line 74
    iget-boolean p2, p0, Lh01/o;->r:Z

    .line 75
    .line 76
    if-nez p2, :cond_9

    .line 77
    .line 78
    move p2, p1

    .line 79
    goto :goto_1

    .line 80
    :cond_9
    move p2, v0

    .line 81
    :goto_1
    if-eqz p2, :cond_a

    .line 82
    .line 83
    iget-boolean p3, p0, Lh01/o;->s:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 84
    .line 85
    if-nez p3, :cond_a

    .line 86
    .line 87
    move v0, p1

    .line 88
    :cond_a
    move v2, v0

    .line 89
    move v0, p2

    .line 90
    move p2, v2

    .line 91
    goto :goto_3

    .line 92
    :goto_2
    monitor-exit p0

    .line 93
    throw p1

    .line 94
    :cond_b
    move p2, v0

    .line 95
    :goto_3
    monitor-exit p0

    .line 96
    if-eqz v0, :cond_c

    .line 97
    .line 98
    const/4 p3, 0x0

    .line 99
    iput-object p3, p0, Lh01/o;->u:Lh01/g;

    .line 100
    .line 101
    iget-object p3, p0, Lh01/o;->l:Lh01/p;

    .line 102
    .line 103
    if-eqz p3, :cond_c

    .line 104
    .line 105
    monitor-enter p3

    .line 106
    :try_start_1
    iget p4, p3, Lh01/p;->m:I

    .line 107
    .line 108
    add-int/2addr p4, p1

    .line 109
    iput p4, p3, Lh01/p;->m:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 110
    .line 111
    monitor-exit p3

    .line 112
    goto :goto_4

    .line 113
    :catchall_1
    move-exception p0

    .line 114
    monitor-exit p3

    .line 115
    throw p0

    .line 116
    :cond_c
    :goto_4
    if-eqz p2, :cond_d

    .line 117
    .line 118
    invoke-virtual {p0, p6}, Lh01/o;->c(Ljava/io/IOException;)Ljava/io/IOException;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    return-object p0

    .line 123
    :cond_d
    :goto_5
    return-object p6
.end method

.method public final h(Ljava/io/IOException;)Ljava/io/IOException;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lh01/o;->s:Z

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iput-boolean v1, p0, Lh01/o;->s:Z

    .line 8
    .line 9
    iget-boolean v0, p0, Lh01/o;->o:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget-boolean v0, p0, Lh01/o;->p:Z

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    iget-boolean v0, p0, Lh01/o;->q:Z

    .line 18
    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    iget-boolean v0, p0, Lh01/o;->r:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception p1

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    :goto_0
    monitor-exit p0

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lh01/o;->c(Ljava/io/IOException;)Ljava/io/IOException;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :cond_1
    return-object p1

    .line 38
    :goto_1
    monitor-exit p0

    .line 39
    throw p1
.end method

.method public final i()Ljava/net/Socket;
    .locals 6

    .line 1
    iget-object v0, p0, Lh01/o;->l:Lh01/p;

    .line 2
    .line 3
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 7
    .line 8
    iget-object v1, v0, Lh01/p;->p:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    const/4 v3, 0x0

    .line 15
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    const/4 v5, -0x1

    .line 20
    if-eqz v4, :cond_1

    .line 21
    .line 22
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    check-cast v4, Ljava/lang/ref/Reference;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-eqz v4, :cond_0

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    move v3, v5

    .line 43
    :goto_1
    if-eq v3, v5, :cond_5

    .line 44
    .line 45
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    const/4 v2, 0x0

    .line 49
    iput-object v2, p0, Lh01/o;->l:Lh01/p;

    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_4

    .line 56
    .line 57
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 58
    .line 59
    .line 60
    move-result-wide v3

    .line 61
    iput-wide v3, v0, Lh01/p;->q:J

    .line 62
    .line 63
    iget-object p0, p0, Lh01/o;->g:Lh01/q;

    .line 64
    .line 65
    iget-object v1, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v1, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 68
    .line 69
    iget-object v3, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v3, Lg01/b;

    .line 72
    .line 73
    sget-object v4, Le01/g;->a:Ljava/util/TimeZone;

    .line 74
    .line 75
    iget-boolean v4, v0, Lh01/p;->j:Z

    .line 76
    .line 77
    if-nez v4, :cond_2

    .line 78
    .line 79
    iget-object p0, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Lf01/e;

    .line 82
    .line 83
    invoke-static {v3, p0}, Lg01/b;->e(Lg01/b;Lg01/a;)V

    .line 84
    .line 85
    .line 86
    return-object v2

    .line 87
    :cond_2
    const/4 p0, 0x1

    .line 88
    iput-boolean p0, v0, Lh01/p;->j:Z

    .line 89
    .line 90
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->remove(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1}, Ljava/util/concurrent/ConcurrentLinkedQueue;->isEmpty()Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    if-eqz p0, :cond_3

    .line 98
    .line 99
    invoke-virtual {v3}, Lg01/b;->a()V

    .line 100
    .line 101
    .line 102
    :cond_3
    iget-object p0, v0, Lh01/p;->e:Ljava/net/Socket;

    .line 103
    .line 104
    return-object p0

    .line 105
    :cond_4
    return-object v2

    .line 106
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 107
    .line 108
    const-string v0, "Check failed."

    .line 109
    .line 110
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0
.end method

.method public final isCanceled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lh01/o;->t:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isExecuted()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh01/o;->i:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final request()Ld01/k0;
    .locals 0

    .line 1
    iget-object p0, p0, Lh01/o;->e:Ld01/k0;

    .line 2
    .line 3
    return-object p0
.end method

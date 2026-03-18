.class public final Ll2/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ll2/a0;

.field public final b:Ll2/x;

.field public final c:Ll2/t;

.field public final d:Lay0/n;

.field public final e:Z

.field public final f:Leb/j0;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/util/concurrent/atomic/AtomicReference;

.field public i:Landroidx/collection/r0;

.field public final j:Ljp/uf;

.field public final k:Lil/g;


# direct methods
.method public constructor <init>(Ll2/a0;Ll2/x;Ll2/t;Landroidx/collection/t0;Lay0/n;ZLeb/j0;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/m1;->a:Ll2/a0;

    .line 5
    .line 6
    iput-object p2, p0, Ll2/m1;->b:Ll2/x;

    .line 7
    .line 8
    iput-object p3, p0, Ll2/m1;->c:Ll2/t;

    .line 9
    .line 10
    iput-object p5, p0, Ll2/m1;->d:Lay0/n;

    .line 11
    .line 12
    iput-boolean p6, p0, Ll2/m1;->e:Z

    .line 13
    .line 14
    iput-object p7, p0, Ll2/m1;->f:Leb/j0;

    .line 15
    .line 16
    iput-object p8, p0, Ll2/m1;->g:Ljava/lang/Object;

    .line 17
    .line 18
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 19
    .line 20
    sget-object p2, Ll2/n1;->f:Ll2/n1;

    .line 21
    .line 22
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 26
    .line 27
    sget-object p1, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 28
    .line 29
    const-string p2, "null cannot be cast to non-null type androidx.collection.ScatterSet<E of androidx.collection.ScatterSetKt.emptyScatterSet>"

    .line 30
    .line 31
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Ll2/m1;->i:Landroidx/collection/r0;

    .line 35
    .line 36
    new-instance p1, Ljp/uf;

    .line 37
    .line 38
    invoke-direct {p1}, Ljp/uf;-><init>()V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p3}, Ll2/t;->z()Lw2/b;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-virtual {p1, p4, p2}, Ljp/uf;->g(Ljava/util/Set;Lw2/b;)V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Ll2/m1;->j:Ljp/uf;

    .line 49
    .line 50
    new-instance p1, Lil/g;

    .line 51
    .line 52
    iget-object p2, p7, Leb/j0;->g:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-direct {p1, p2}, Lil/g;-><init>(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iput-object p1, p0, Ll2/m1;->k:Lil/g;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    :try_start_0
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ll2/n1;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    new-instance p0, La8/r0;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :catch_0
    move-exception p0

    .line 23
    goto :goto_0

    .line 24
    :pswitch_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string v1, "The paused composition has already been applied"

    .line 27
    .line 28
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :pswitch_1
    invoke-virtual {p0}, Ll2/m1;->b()V

    .line 33
    .line 34
    .line 35
    sget-object p0, Ll2/n1;->i:Ll2/n1;

    .line 36
    .line 37
    sget-object v1, Ll2/n1;->j:Ll2/n1;

    .line 38
    .line 39
    :cond_0
    invoke-virtual {v0, p0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-eqz v2, :cond_1

    .line 44
    .line 45
    return-void

    .line 46
    :cond_1
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    if-eq v2, p0, :cond_0

    .line 51
    .line 52
    new-instance v2, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 55
    .line 56
    .line 57
    const-string v3, "Unexpected state change from: "

    .line 58
    .line 59
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string p0, " to: "

    .line 66
    .line 67
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const/16 p0, 0x2e

    .line 74
    .line 75
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-static {p0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :pswitch_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    const-string v1, "The paused composition has not completed yet"

    .line 89
    .line 90
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :pswitch_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    const-string v1, "The paused composition has been cancelled"

    .line 97
    .line 98
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0

    .line 102
    :pswitch_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 103
    .line 104
    const-string v1, "The paused composition is invalid because of a previous exception"

    .line 105
    .line 106
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 110
    :goto_0
    sget-object v1, Ll2/n1;->d:Ll2/n1;

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()V
    .locals 5

    .line 1
    iget-object v0, p0, Ll2/m1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :try_start_0
    iget-object v2, p0, Ll2/m1;->k:Lil/g;

    .line 6
    .line 7
    iget-object v3, p0, Ll2/m1;->f:Leb/j0;

    .line 8
    .line 9
    iget-object v4, p0, Ll2/m1;->j:Ljp/uf;

    .line 10
    .line 11
    invoke-virtual {v2, v3, v4}, Lil/g;->S(Leb/j0;Ljp/uf;)V

    .line 12
    .line 13
    .line 14
    iget-object v2, p0, Ll2/m1;->j:Ljp/uf;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljp/uf;->c()V

    .line 17
    .line 18
    .line 19
    iget-object v2, p0, Ll2/m1;->j:Ljp/uf;

    .line 20
    .line 21
    invoke-virtual {v2}, Ljp/uf;->d()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 22
    .line 23
    .line 24
    :try_start_1
    iget-object v2, p0, Ll2/m1;->j:Ljp/uf;

    .line 25
    .line 26
    invoke-virtual {v2}, Ljp/uf;->b()V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Ll2/m1;->a:Ll2/a0;

    .line 30
    .line 31
    iput-object v1, p0, Ll2/a0;->t:Ll2/m1;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 32
    .line 33
    monitor-exit v0

    .line 34
    return-void

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_0

    .line 37
    :catchall_1
    move-exception v2

    .line 38
    :try_start_2
    iget-object v3, p0, Ll2/m1;->j:Ljp/uf;

    .line 39
    .line 40
    invoke-virtual {v3}, Ljp/uf;->b()V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Ll2/m1;->a:Ll2/a0;

    .line 44
    .line 45
    iput-object v1, p0, Ll2/a0;->t:Ll2/m1;

    .line 46
    .line 47
    throw v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 48
    :goto_0
    monitor-exit v0

    .line 49
    throw p0
.end method

.method public final c()Z
    .locals 1

    .line 1
    iget-object p0, p0, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ll2/n1;

    .line 8
    .line 9
    sget-object v0, Ll2/n1;->i:Ll2/n1;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-ltz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final d()V
    .locals 4

    .line 1
    sget-object v0, Ll2/n1;->g:Ll2/n1;

    .line 2
    .line 3
    sget-object v1, Ll2/n1;->i:Ll2/n1;

    .line 4
    .line 5
    :cond_0
    iget-object v2, p0, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 6
    .line 7
    invoke-virtual {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    if-eqz v3, :cond_1

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    goto :goto_0

    .line 15
    :cond_1
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    if-eq v2, v0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    :goto_0
    if-nez p0, :cond_2

    .line 23
    .line 24
    new-instance p0, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v2, "Unexpected state change from: "

    .line 27
    .line 28
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v0, " to: "

    .line 35
    .line 36
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const/16 v0, 0x2e

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-static {p0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_2
    return-void
.end method

.method public final e()V
    .locals 3

    .line 1
    iget-object p0, p0, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Ll2/n1;->g:Ll2/n1;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    sget-object v0, Ll2/n1;->i:Ll2/n1;

    .line 13
    .line 14
    :cond_1
    invoke-virtual {p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_2

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_2
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    if-eq v2, v0, :cond_1

    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    :goto_0
    if-nez p0, :cond_3

    .line 30
    .line 31
    new-instance p0, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v2, "Unexpected state change from: "

    .line 34
    .line 35
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v0, " to: "

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const/16 v0, 0x2e

    .line 50
    .line 51
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-static {p0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    :cond_3
    :goto_1
    return-void
.end method

.method public final f(Lt0/c;)Z
    .locals 9

    .line 1
    iget-object v0, p0, Ll2/m1;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    :try_start_0
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ll2/n1;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 10
    .line 11
    .line 12
    move-result v1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    iget-object v2, p0, Ll2/m1;->a:Ll2/a0;

    .line 14
    .line 15
    iget-object v3, p0, Ll2/m1;->b:Ll2/x;

    .line 16
    .line 17
    const/16 v4, 0x2e

    .line 18
    .line 19
    const-string v5, " to: "

    .line 20
    .line 21
    const-string v6, "Unexpected state change from: "

    .line 22
    .line 23
    packed-switch v1, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    :try_start_1
    new-instance p0, La8/r0;

    .line 27
    .line 28
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :catch_0
    move-exception p0

    .line 33
    goto/16 :goto_5

    .line 34
    .line 35
    :pswitch_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string p1, "The paused composition has been applied"

    .line 38
    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :pswitch_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "Pausable composition is complete and apply() should be applied"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :pswitch_2
    const-string p0, "Recursive call to resume()"

    .line 52
    .line 53
    invoke-static {p0}, Ll2/v;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 54
    .line 55
    .line 56
    new-instance p0, La8/r0;

    .line 57
    .line 58
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :pswitch_3
    sget-object v1, Ll2/n1;->g:Ll2/n1;

    .line 63
    .line 64
    sget-object v7, Ll2/n1;->h:Ll2/n1;

    .line 65
    .line 66
    :cond_0
    invoke-virtual {v0, v1, v7}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    if-eqz v8, :cond_1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v8

    .line 77
    if-eq v8, v1, :cond_0

    .line 78
    .line 79
    new-instance v8, Ljava/lang/StringBuilder;

    .line 80
    .line 81
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    invoke-static {v1}, Ll2/q1;->b(Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 104
    .line 105
    .line 106
    :goto_0
    :try_start_2
    iget-object v1, p0, Ll2/m1;->i:Landroidx/collection/r0;

    .line 107
    .line 108
    invoke-virtual {v3, v2, p1, v1}, Ll2/x;->m(Ll2/a0;Lt0/c;Landroidx/collection/r0;)Landroidx/collection/r0;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    iput-object p1, p0, Ll2/m1;->i:Landroidx/collection/r0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 113
    .line 114
    :try_start_3
    sget-object p1, Ll2/n1;->h:Ll2/n1;

    .line 115
    .line 116
    sget-object v1, Ll2/n1;->g:Ll2/n1;

    .line 117
    .line 118
    :cond_2
    invoke-virtual {v0, p1, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    if-eqz v2, :cond_3

    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    if-eq v2, p1, :cond_2

    .line 130
    .line 131
    new-instance v2, Ljava/lang/StringBuilder;

    .line 132
    .line 133
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    invoke-static {p1}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    :goto_1
    iget-object p1, p0, Ll2/m1;->i:Landroidx/collection/r0;

    .line 159
    .line 160
    invoke-virtual {p1}, Landroidx/collection/r0;->g()Z

    .line 161
    .line 162
    .line 163
    move-result p1

    .line 164
    if-eqz p1, :cond_a

    .line 165
    .line 166
    invoke-virtual {p0}, Ll2/m1;->d()V

    .line 167
    .line 168
    .line 169
    goto/16 :goto_4

    .line 170
    .line 171
    :catchall_0
    move-exception p0

    .line 172
    sget-object p1, Ll2/n1;->h:Ll2/n1;

    .line 173
    .line 174
    sget-object v1, Ll2/n1;->g:Ll2/n1;

    .line 175
    .line 176
    :goto_2
    invoke-virtual {v0, p1, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v2

    .line 180
    if-nez v2, :cond_5

    .line 181
    .line 182
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    if-ne v2, p1, :cond_4

    .line 187
    .line 188
    goto :goto_2

    .line 189
    :cond_4
    new-instance v2, Ljava/lang/StringBuilder;

    .line 190
    .line 191
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 195
    .line 196
    .line 197
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object p1

    .line 213
    invoke-static {p1}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    :cond_5
    throw p0
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 217
    :pswitch_4
    iget-object v1, p0, Ll2/m1;->c:Ll2/t;

    .line 218
    .line 219
    iget-boolean v7, p0, Ll2/m1;->e:Z

    .line 220
    .line 221
    if-eqz v7, :cond_6

    .line 222
    .line 223
    const/16 v8, 0x64

    .line 224
    .line 225
    :try_start_4
    iput v8, v1, Ll2/t;->z:I

    .line 226
    .line 227
    const/4 v8, 0x1

    .line 228
    iput-boolean v8, v1, Ll2/t;->y:Z
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 229
    .line 230
    :cond_6
    :try_start_5
    iget-object v8, p0, Ll2/m1;->d:Lay0/n;

    .line 231
    .line 232
    invoke-virtual {v3, v2, p1, v8}, Ll2/x;->b(Ll2/a0;Lt0/c;Lay0/n;)Landroidx/collection/r0;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    iput-object p1, p0, Ll2/m1;->i:Landroidx/collection/r0;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 237
    .line 238
    if-eqz v7, :cond_7

    .line 239
    .line 240
    :try_start_6
    invoke-virtual {v1}, Ll2/t;->t()V

    .line 241
    .line 242
    .line 243
    :cond_7
    sget-object p1, Ll2/n1;->f:Ll2/n1;

    .line 244
    .line 245
    sget-object v1, Ll2/n1;->g:Ll2/n1;

    .line 246
    .line 247
    :cond_8
    invoke-virtual {v0, p1, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v2

    .line 251
    if-eqz v2, :cond_9

    .line 252
    .line 253
    goto :goto_3

    .line 254
    :cond_9
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    if-eq v2, p1, :cond_8

    .line 259
    .line 260
    new-instance v2, Ljava/lang/StringBuilder;

    .line 261
    .line 262
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 266
    .line 267
    .line 268
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 269
    .line 270
    .line 271
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 272
    .line 273
    .line 274
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 275
    .line 276
    .line 277
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 278
    .line 279
    .line 280
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object p1

    .line 284
    invoke-static {p1}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    :goto_3
    iget-object p1, p0, Ll2/m1;->i:Landroidx/collection/r0;

    .line 288
    .line 289
    invoke-virtual {p1}, Landroidx/collection/r0;->g()Z

    .line 290
    .line 291
    .line 292
    move-result p1

    .line 293
    if-eqz p1, :cond_a

    .line 294
    .line 295
    invoke-virtual {p0}, Ll2/m1;->d()V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0

    .line 296
    .line 297
    .line 298
    :cond_a
    :goto_4
    invoke-virtual {p0}, Ll2/m1;->c()Z

    .line 299
    .line 300
    .line 301
    move-result p0

    .line 302
    return p0

    .line 303
    :catchall_1
    move-exception p0

    .line 304
    if-eqz v7, :cond_b

    .line 305
    .line 306
    :try_start_7
    invoke-virtual {v1}, Ll2/t;->t()V

    .line 307
    .line 308
    .line 309
    :cond_b
    throw p0

    .line 310
    :pswitch_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 311
    .line 312
    const-string p1, "The paused composition has been cancelled"

    .line 313
    .line 314
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    throw p0

    .line 318
    :pswitch_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 319
    .line 320
    const-string p1, "The paused composition is invalid because of a previous exception"

    .line 321
    .line 322
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    throw p0
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_0

    .line 326
    :goto_5
    sget-object p1, Ll2/n1;->d:Ll2/n1;

    .line 327
    .line 328
    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    throw p0

    .line 332
    nop

    .line 333
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

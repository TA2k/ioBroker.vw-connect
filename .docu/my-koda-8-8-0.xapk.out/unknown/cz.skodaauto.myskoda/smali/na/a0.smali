.class public final Lna/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lla/c0;
.implements Lna/b0;


# instance fields
.field public final a:Ldv/a;

.field public final b:Lna/g;

.field public final c:Z

.field public final d:Lmx0/l;

.field public final e:Ljava/util/concurrent/atomic/AtomicBoolean;


# direct methods
.method public constructor <init>(Ldv/a;Lna/g;Z)V
    .locals 1

    .line 1
    const-string v0, "connectionElementKey"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lna/a0;->a:Ldv/a;

    .line 10
    .line 11
    iput-object p2, p0, Lna/a0;->b:Lna/g;

    .line 12
    .line 13
    iput-boolean p3, p0, Lna/a0;->c:Z

    .line 14
    .line 15
    new-instance p1, Lmx0/l;

    .line 16
    .line 17
    invoke-direct {p1}, Lmx0/l;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lna/a0;->d:Lmx0/l;

    .line 21
    .line 22
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 23
    .line 24
    const/4 p2, 0x0

    .line 25
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lna/a0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p3, Lna/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lna/z;

    .line 7
    .line 8
    iget v1, v0, Lna/z;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lna/z;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lna/z;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lna/z;-><init>(Lna/a0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lna/z;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lna/z;->i:I

    .line 30
    .line 31
    iget-object v3, p0, Lna/a0;->b:Lna/g;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    const/4 v5, 0x0

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v4, :cond_1

    .line 38
    .line 39
    iget-object p1, v0, Lna/z;->f:Lna/g;

    .line 40
    .line 41
    iget-object p2, v0, Lna/z;->e:Lay0/k;

    .line 42
    .line 43
    iget-object v0, v0, Lna/z;->d:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    move-object p3, p2

    .line 49
    move-object p2, p1

    .line 50
    move-object p1, v0

    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object p3, p0, Lna/a0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 64
    .line 65
    invoke-virtual {p3}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 66
    .line 67
    .line 68
    move-result p3

    .line 69
    const/16 v2, 0x15

    .line 70
    .line 71
    if-nez p3, :cond_5

    .line 72
    .line 73
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    iget-object v6, p0, Lna/a0;->a:Ldv/a;

    .line 78
    .line 79
    invoke-interface {p3, v6}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 80
    .line 81
    .line 82
    move-result-object p3

    .line 83
    check-cast p3, Lna/a;

    .line 84
    .line 85
    if-eqz p3, :cond_4

    .line 86
    .line 87
    iget-object p3, p3, Lna/a;->e:Lna/a0;

    .line 88
    .line 89
    if-ne p3, p0, :cond_4

    .line 90
    .line 91
    iput-object p1, v0, Lna/z;->d:Ljava/lang/String;

    .line 92
    .line 93
    iput-object p2, v0, Lna/z;->e:Lay0/k;

    .line 94
    .line 95
    iput-object v3, v0, Lna/z;->f:Lna/g;

    .line 96
    .line 97
    iput v4, v0, Lna/z;->i:I

    .line 98
    .line 99
    iget-object p3, v3, Lna/g;->e:Lez0/a;

    .line 100
    .line 101
    invoke-interface {p3, v0}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p3

    .line 105
    if-ne p3, v1, :cond_3

    .line 106
    .line 107
    return-object v1

    .line 108
    :cond_3
    move-object p3, p2

    .line 109
    move-object p2, v3

    .line 110
    :goto_1
    :try_start_0
    new-instance v0, Lna/u;

    .line 111
    .line 112
    invoke-virtual {v3, p1}, Lna/g;->v0(Ljava/lang/String;)Lua/c;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    invoke-direct {v0, p0, p1}, Lna/u;-><init>(Lna/a0;Lua/c;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 117
    .line 118
    .line 119
    :try_start_1
    invoke-interface {p3, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 123
    :try_start_2
    invoke-static {v0, v5}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 124
    .line 125
    .line 126
    invoke-interface {p2, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    return-object p0

    .line 130
    :catchall_0
    move-exception p0

    .line 131
    goto :goto_2

    .line 132
    :catchall_1
    move-exception p0

    .line 133
    :try_start_3
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 134
    :catchall_2
    move-exception p1

    .line 135
    :try_start_4
    invoke-static {v0, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 136
    .line 137
    .line 138
    throw p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 139
    :goto_2
    invoke-interface {p2, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    throw p0

    .line 143
    :cond_4
    const-string p0, "Attempted to use connection on a different coroutine"

    .line 144
    .line 145
    invoke-static {v2, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw v5

    .line 149
    :cond_5
    const-string p0, "Connection is recycled"

    .line 150
    .line 151
    invoke-static {v2, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw v5
.end method

.method public final b(Lla/b0;Lay0/n;Lrx0/i;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lna/a0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    const/16 v2, 0x15

    .line 9
    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    invoke-interface {p3}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget-object v3, p0, Lna/a0;->a:Ldv/a;

    .line 17
    .line 18
    invoke-interface {v0, v3}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lna/a;

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    iget-object v0, v0, Lna/a;->e:Lna/a0;

    .line 27
    .line 28
    if-ne v0, p0, :cond_0

    .line 29
    .line 30
    invoke-virtual {p0, p1, p2, p3}, Lna/a0;->g(Lla/b0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :cond_0
    const-string p0, "Attempted to use connection on a different coroutine"

    .line 36
    .line 37
    invoke-static {v2, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw v1

    .line 41
    :cond_1
    const-string p0, "Connection is recycled"

    .line 42
    .line 43
    invoke-static {v2, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw v1
.end method

.method public final c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;
    .locals 3

    .line 1
    iget-object v0, p0, Lna/a0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    const/16 v2, 0x15

    .line 9
    .line 10
    if-nez v0, :cond_3

    .line 11
    .line 12
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iget-object v0, p0, Lna/a0;->a:Ldv/a;

    .line 17
    .line 18
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Lna/a;

    .line 23
    .line 24
    if-eqz p1, :cond_2

    .line 25
    .line 26
    iget-object p1, p1, Lna/a;->e:Lna/a0;

    .line 27
    .line 28
    if-ne p1, p0, :cond_2

    .line 29
    .line 30
    iget-object p1, p0, Lna/a0;->d:Lmx0/l;

    .line 31
    .line 32
    invoke-virtual {p1}, Lmx0/l;->isEmpty()Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-eqz p1, :cond_1

    .line 37
    .line 38
    iget-object p0, p0, Lna/a0;->b:Lna/g;

    .line 39
    .line 40
    iget-object p0, p0, Lna/g;->d:Lua/a;

    .line 41
    .line 42
    invoke-interface {p0}, Lua/a;->inTransaction()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    const/4 p0, 0x0

    .line 50
    goto :goto_1

    .line 51
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 52
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :cond_2
    const-string p0, "Attempted to use connection on a different coroutine"

    .line 58
    .line 59
    invoke-static {v2, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw v1

    .line 63
    :cond_3
    const-string p0, "Connection is recycled"

    .line 64
    .line 65
    invoke-static {v2, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v1
.end method

.method public final d()Lua/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lna/a0;->b:Lna/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e(Lla/b0;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lna/a0;->d:Lmx0/l;

    .line 2
    .line 3
    const-string v1, "SAVEPOINT \'"

    .line 4
    .line 5
    instance-of v2, p2, Lna/w;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, p2

    .line 10
    check-cast v2, Lna/w;

    .line 11
    .line 12
    iget v3, v2, Lna/w;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lna/w;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lna/w;

    .line 25
    .line 26
    invoke-direct {v2, p0, p2}, Lna/w;-><init>(Lna/a0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p2, v2, Lna/w;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lna/w;->h:I

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    iget-object p0, p0, Lna/a0;->b:Lna/g;

    .line 37
    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    if-ne v4, v5, :cond_1

    .line 41
    .line 42
    iget-object p1, v2, Lna/w;->e:Lna/g;

    .line 43
    .line 44
    iget-object v2, v2, Lna/w;->d:Lla/b0;

    .line 45
    .line 46
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move-object p2, p1

    .line 50
    move-object p1, v2

    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iput-object p1, v2, Lna/w;->d:Lla/b0;

    .line 64
    .line 65
    iput-object p0, v2, Lna/w;->e:Lna/g;

    .line 66
    .line 67
    iput v5, v2, Lna/w;->h:I

    .line 68
    .line 69
    iget-object p2, p0, Lna/g;->e:Lez0/a;

    .line 70
    .line 71
    invoke-interface {p2, v2}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    if-ne p2, v3, :cond_3

    .line 76
    .line 77
    return-object v3

    .line 78
    :cond_3
    move-object p2, p0

    .line 79
    :goto_1
    const/4 v2, 0x0

    .line 80
    :try_start_0
    iget v3, v0, Lmx0/l;->f:I

    .line 81
    .line 82
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    if-eqz v4, :cond_7

    .line 87
    .line 88
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 89
    .line 90
    .line 91
    move-result p1

    .line 92
    if-eqz p1, :cond_6

    .line 93
    .line 94
    if-eq p1, v5, :cond_5

    .line 95
    .line 96
    const/4 v1, 0x2

    .line 97
    if-ne p1, v1, :cond_4

    .line 98
    .line 99
    const-string p1, "BEGIN EXCLUSIVE TRANSACTION"

    .line 100
    .line 101
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    goto :goto_2

    .line 105
    :catchall_0
    move-exception p0

    .line 106
    goto :goto_3

    .line 107
    :cond_4
    new-instance p0, La8/r0;

    .line 108
    .line 109
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 110
    .line 111
    .line 112
    throw p0

    .line 113
    :cond_5
    const-string p1, "BEGIN IMMEDIATE TRANSACTION"

    .line 114
    .line 115
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_6
    const-string p1, "BEGIN DEFERRED TRANSACTION"

    .line 120
    .line 121
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_7
    new-instance p1, Ljava/lang/StringBuilder;

    .line 126
    .line 127
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const/16 v1, 0x27

    .line 134
    .line 135
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    :goto_2
    new-instance p0, Lna/v;

    .line 146
    .line 147
    invoke-direct {p0, v3}, Lna/v;-><init>(I)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0, p0}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    sget-object p0, Llx0/b0;->a:Llx0/b0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 154
    .line 155
    invoke-interface {p2, v2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    return-object p0

    .line 159
    :goto_3
    invoke-interface {p2, v2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    throw p0
.end method

.method public final f(ZLrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lna/a0;->d:Lmx0/l;

    .line 2
    .line 3
    const-string v1, "ROLLBACK TRANSACTION TO SAVEPOINT \'"

    .line 4
    .line 5
    const-string v2, "RELEASE SAVEPOINT \'"

    .line 6
    .line 7
    instance-of v3, p2, Lna/x;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, p2

    .line 12
    check-cast v3, Lna/x;

    .line 13
    .line 14
    iget v4, v3, Lna/x;->h:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lna/x;->h:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lna/x;

    .line 27
    .line 28
    invoke-direct {v3, p0, p2}, Lna/x;-><init>(Lna/a0;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object p2, v3, Lna/x;->f:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lna/x;->h:I

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    iget-object p0, p0, Lna/a0;->b:Lna/g;

    .line 39
    .line 40
    if-eqz v5, :cond_2

    .line 41
    .line 42
    if-ne v5, v6, :cond_1

    .line 43
    .line 44
    iget-boolean p1, v3, Lna/x;->d:Z

    .line 45
    .line 46
    iget-object v3, v3, Lna/x;->e:Lna/g;

    .line 47
    .line 48
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iput-object p0, v3, Lna/x;->e:Lna/g;

    .line 64
    .line 65
    iput-boolean p1, v3, Lna/x;->d:Z

    .line 66
    .line 67
    iput v6, v3, Lna/x;->h:I

    .line 68
    .line 69
    iget-object p2, p0, Lna/g;->e:Lez0/a;

    .line 70
    .line 71
    invoke-interface {p2, v3}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    if-ne p2, v4, :cond_3

    .line 76
    .line 77
    return-object v4

    .line 78
    :cond_3
    move-object v3, p0

    .line 79
    :goto_1
    const/4 p2, 0x0

    .line 80
    :try_start_0
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    if-nez v4, :cond_7

    .line 85
    .line 86
    invoke-static {v0}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    check-cast v4, Lna/v;

    .line 91
    .line 92
    const/16 v5, 0x27

    .line 93
    .line 94
    if-eqz p1, :cond_5

    .line 95
    .line 96
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    if-eqz p1, :cond_4

    .line 104
    .line 105
    const-string p1, "END TRANSACTION"

    .line 106
    .line 107
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    goto :goto_2

    .line 111
    :catchall_0
    move-exception p0

    .line 112
    goto :goto_3

    .line 113
    :cond_4
    new-instance p1, Ljava/lang/StringBuilder;

    .line 114
    .line 115
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    iget v0, v4, Lna/v;->a:I

    .line 119
    .line 120
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {p1, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_5
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    if-eqz p1, :cond_6

    .line 139
    .line 140
    const-string p1, "ROLLBACK TRANSACTION"

    .line 141
    .line 142
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    goto :goto_2

    .line 146
    :cond_6
    new-instance p1, Ljava/lang/StringBuilder;

    .line 147
    .line 148
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    iget v0, v4, Lna/v;->a:I

    .line 152
    .line 153
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {p1, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-static {p0, p1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 167
    .line 168
    invoke-interface {v3, p2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    return-object p0

    .line 172
    :cond_7
    :try_start_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 173
    .line 174
    const-string p1, "Not in a transaction"

    .line 175
    .line 176
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 180
    :goto_3
    invoke-interface {v3, p2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    throw p0
.end method

.method public final g(Lla/b0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p3, Lna/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lna/y;

    .line 7
    .line 8
    iget v1, v0, Lna/y;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lna/y;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lna/y;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lna/y;-><init>(Lna/a0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lna/y;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lna/y;->i:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x5

    .line 33
    const/4 v5, 0x3

    .line 34
    const/4 v6, 0x2

    .line 35
    const/4 v7, 0x1

    .line 36
    if-eqz v2, :cond_5

    .line 37
    .line 38
    if-eq v2, v7, :cond_4

    .line 39
    .line 40
    if-eq v2, v6, :cond_3

    .line 41
    .line 42
    if-eq v2, v5, :cond_2

    .line 43
    .line 44
    const/4 p0, 0x4

    .line 45
    if-eq v2, p0, :cond_2

    .line 46
    .line 47
    if-eq v2, v4, :cond_1

    .line 48
    .line 49
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_1
    iget-object p0, v0, Lna/y;->e:Ljava/lang/Throwable;

    .line 58
    .line 59
    iget-object p1, v0, Lna/y;->d:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p1, Ljava/lang/Throwable;

    .line 62
    .line 63
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    .line 64
    .line 65
    .line 66
    goto/16 :goto_6

    .line 67
    .line 68
    :catch_0
    move-exception p2

    .line 69
    goto/16 :goto_5

    .line 70
    .line 71
    :cond_2
    iget-object p0, v0, Lna/y;->d:Ljava/lang/Object;

    .line 72
    .line 73
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_3
    iget p1, v0, Lna/y;->f:I

    .line 78
    .line 79
    :try_start_1
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :catchall_0
    move-exception p1

    .line 84
    goto :goto_3

    .line 85
    :cond_4
    iget-object p1, v0, Lna/y;->d:Ljava/lang/Object;

    .line 86
    .line 87
    move-object p2, p1

    .line 88
    check-cast p2, Lay0/n;

    .line 89
    .line 90
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_5
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    if-nez p1, :cond_6

    .line 98
    .line 99
    sget-object p1, Lla/b0;->d:Lla/b0;

    .line 100
    .line 101
    :cond_6
    iput-object p2, v0, Lna/y;->d:Ljava/lang/Object;

    .line 102
    .line 103
    iput v7, v0, Lna/y;->i:I

    .line 104
    .line 105
    invoke-virtual {p0, p1, v0}, Lna/a0;->e(Lla/b0;Lrx0/c;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    if-ne p1, v1, :cond_7

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_7
    :goto_1
    :try_start_2
    new-instance p1, Lna/k;

    .line 113
    .line 114
    const/4 p3, 0x1

    .line 115
    invoke-direct {p1, p0, p3}, Lna/k;-><init>(Ljava/lang/Object;I)V

    .line 116
    .line 117
    .line 118
    const/4 p3, 0x0

    .line 119
    iput-object p3, v0, Lna/y;->d:Ljava/lang/Object;

    .line 120
    .line 121
    iput v7, v0, Lna/y;->f:I

    .line 122
    .line 123
    iput v6, v0, Lna/y;->i:I

    .line 124
    .line 125
    invoke-interface {p2, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 129
    if-ne p3, v1, :cond_8

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_8
    move p1, v7

    .line 133
    :goto_2
    if-eqz p1, :cond_9

    .line 134
    .line 135
    move v3, v7

    .line 136
    :cond_9
    iput-object p3, v0, Lna/y;->d:Ljava/lang/Object;

    .line 137
    .line 138
    iput v5, v0, Lna/y;->i:I

    .line 139
    .line 140
    invoke-virtual {p0, v3, v0}, Lna/a0;->f(ZLrx0/c;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-ne p0, v1, :cond_a

    .line 145
    .line 146
    goto :goto_4

    .line 147
    :cond_a
    return-object p3

    .line 148
    :goto_3
    :try_start_3
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 149
    :catchall_1
    move-exception p2

    .line 150
    :try_start_4
    iput-object p1, v0, Lna/y;->d:Ljava/lang/Object;

    .line 151
    .line 152
    iput-object p2, v0, Lna/y;->e:Ljava/lang/Throwable;

    .line 153
    .line 154
    iput v4, v0, Lna/y;->i:I

    .line 155
    .line 156
    invoke-virtual {p0, v3, v0}, Lna/a0;->f(ZLrx0/c;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object p0
    :try_end_4
    .catch Landroid/database/SQLException; {:try_start_4 .. :try_end_4} :catch_1

    .line 160
    if-ne p0, v1, :cond_b

    .line 161
    .line 162
    :goto_4
    return-object v1

    .line 163
    :cond_b
    move-object p0, p2

    .line 164
    goto :goto_6

    .line 165
    :catch_1
    move-exception p0

    .line 166
    move-object v8, p2

    .line 167
    move-object p2, p0

    .line 168
    move-object p0, v8

    .line 169
    :goto_5
    if-eqz p1, :cond_c

    .line 170
    .line 171
    invoke-static {p1, p2}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 172
    .line 173
    .line 174
    :goto_6
    throw p0

    .line 175
    :cond_c
    throw p2
.end method

.class public final Lna/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lla/c0;
.implements Lna/b0;


# instance fields
.field public final a:Lkotlin/jvm/internal/k;

.field public final b:Lua/a;

.field public final c:Ljava/util/concurrent/atomic/AtomicInteger;

.field public d:Lla/b0;


# direct methods
.method public constructor <init>(Lay0/n;Lua/a;)V
    .locals 1

    .line 1
    const-string v0, "delegate"

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
    check-cast p1, Lkotlin/jvm/internal/k;

    .line 10
    .line 11
    iput-object p1, p0, Lna/o;->a:Lkotlin/jvm/internal/k;

    .line 12
    .line 13
    iput-object p2, p0, Lna/o;->b:Lua/a;

    .line 14
    .line 15
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lna/o;->c:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lna/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lna/m;

    .line 7
    .line 8
    iget v1, v0, Lna/m;->h:I

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
    iput v1, v0, Lna/m;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lna/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lna/m;-><init>(Lna/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lna/m;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lna/m;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget-object p2, v0, Lna/m;->e:Lay0/k;

    .line 52
    .line 53
    iget-object p1, v0, Lna/m;->d:Ljava/lang/String;

    .line 54
    .line 55
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput-object p1, v0, Lna/m;->d:Ljava/lang/String;

    .line 63
    .line 64
    iput-object p2, v0, Lna/m;->e:Lay0/k;

    .line 65
    .line 66
    iput v4, v0, Lna/m;->h:I

    .line 67
    .line 68
    invoke-virtual {p0, v0}, Lna/o;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 69
    .line 70
    .line 71
    move-result-object p3

    .line 72
    if-ne p3, v1, :cond_4

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_4
    :goto_1
    check-cast p3, Ljava/lang/Boolean;

    .line 76
    .line 77
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 78
    .line 79
    .line 80
    move-result p3

    .line 81
    const/4 v2, 0x0

    .line 82
    if-eqz p3, :cond_6

    .line 83
    .line 84
    new-instance p3, Lna/n;

    .line 85
    .line 86
    invoke-direct {p3, p0, p1, p2, v2}, Lna/n;-><init>(Lna/o;Ljava/lang/String;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 87
    .line 88
    .line 89
    iput-object v2, v0, Lna/m;->d:Ljava/lang/String;

    .line 90
    .line 91
    iput-object v2, v0, Lna/m;->e:Lay0/k;

    .line 92
    .line 93
    iput v3, v0, Lna/m;->h:I

    .line 94
    .line 95
    iget-object p0, p0, Lna/o;->a:Lkotlin/jvm/internal/k;

    .line 96
    .line 97
    invoke-interface {p0, p3, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    if-ne p0, v1, :cond_5

    .line 102
    .line 103
    :goto_2
    return-object v1

    .line 104
    :cond_5
    return-object p0

    .line 105
    :cond_6
    iget-object p0, p0, Lna/o;->b:Lua/a;

    .line 106
    .line 107
    invoke-interface {p0, p1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    :try_start_0
    invoke-interface {p2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 115
    invoke-static {p0, v2}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 116
    .line 117
    .line 118
    return-object p1

    .line 119
    :catchall_0
    move-exception p1

    .line 120
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 121
    :catchall_1
    move-exception p2

    .line 122
    invoke-static {p0, p1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 123
    .line 124
    .line 125
    throw p2
.end method

.method public final b(Lla/b0;Lay0/n;Lrx0/i;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, La30/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, p2, v1}, La30/b;-><init>(Lna/o;Lla/b0;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lna/o;->a:Lkotlin/jvm/internal/k;

    .line 8
    .line 9
    invoke-interface {p0, v0, p3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    return-object p0
.end method

.method public final c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p1, p0, Lna/o;->d:Lla/b0;

    .line 2
    .line 3
    if-nez p1, :cond_1

    .line 4
    .line 5
    iget-object p0, p0, Lna/o;->b:Lua/a;

    .line 6
    .line 7
    invoke-interface {p0}, Lua/a;->inTransaction()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public final d()Lua/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lna/o;->b:Lua/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e(Lla/b0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p3, Lna/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lna/l;

    .line 7
    .line 8
    iget v1, v0, Lna/l;->g:I

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
    iput v1, v0, Lna/l;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lna/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lna/l;-><init>(Lna/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lna/l;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lna/l;->g:I

    .line 30
    .line 31
    const-string v3, "ROLLBACK TRANSACTION"

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    iget-object v5, p0, Lna/o;->c:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 35
    .line 36
    const/4 v6, 0x1

    .line 37
    iget-object v7, p0, Lna/o;->b:Lua/a;

    .line 38
    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    if-ne v2, v6, :cond_1

    .line 42
    .line 43
    iget v6, v0, Lna/l;->d:I

    .line 44
    .line 45
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    .line 47
    .line 48
    goto :goto_2

    .line 49
    :catchall_0
    move-exception p1

    .line 50
    goto :goto_3

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 63
    .line 64
    .line 65
    move-result p3

    .line 66
    if-eqz p3, :cond_5

    .line 67
    .line 68
    if-eq p3, v6, :cond_4

    .line 69
    .line 70
    const/4 v2, 0x2

    .line 71
    if-ne p3, v2, :cond_3

    .line 72
    .line 73
    const-string p3, "BEGIN EXCLUSIVE TRANSACTION"

    .line 74
    .line 75
    invoke-static {v7, p3}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_3
    new-instance p0, La8/r0;

    .line 80
    .line 81
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_4
    const-string p3, "BEGIN IMMEDIATE TRANSACTION"

    .line 86
    .line 87
    invoke-static {v7, p3}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_5
    const-string p3, "BEGIN DEFERRED TRANSACTION"

    .line 92
    .line 93
    invoke-static {v7, p3}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    :goto_1
    invoke-virtual {v5}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 97
    .line 98
    .line 99
    move-result p3

    .line 100
    if-lez p3, :cond_6

    .line 101
    .line 102
    iput-object p1, p0, Lna/o;->d:Lla/b0;

    .line 103
    .line 104
    :cond_6
    :try_start_1
    new-instance p1, Lna/k;

    .line 105
    .line 106
    const/4 p3, 0x0

    .line 107
    invoke-direct {p1, p0, p3}, Lna/k;-><init>(Ljava/lang/Object;I)V

    .line 108
    .line 109
    .line 110
    iput v6, v0, Lna/l;->d:I

    .line 111
    .line 112
    iput v6, v0, Lna/l;->g:I

    .line 113
    .line 114
    invoke-interface {p2, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 118
    if-ne p3, v1, :cond_7

    .line 119
    .line 120
    return-object v1

    .line 121
    :cond_7
    :goto_2
    invoke-virtual {v5}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    if-nez p1, :cond_8

    .line 126
    .line 127
    iput-object v4, p0, Lna/o;->d:Lla/b0;

    .line 128
    .line 129
    :cond_8
    if-eqz v6, :cond_9

    .line 130
    .line 131
    const-string p0, "END TRANSACTION"

    .line 132
    .line 133
    invoke-static {v7, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    return-object p3

    .line 137
    :cond_9
    invoke-static {v7, v3}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    return-object p3

    .line 141
    :goto_3
    :try_start_2
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 142
    :catchall_1
    move-exception p2

    .line 143
    :try_start_3
    invoke-virtual {v5}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 144
    .line 145
    .line 146
    move-result p3

    .line 147
    if-nez p3, :cond_a

    .line 148
    .line 149
    iput-object v4, p0, Lna/o;->d:Lla/b0;

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :catch_0
    move-exception p0

    .line 153
    goto :goto_5

    .line 154
    :cond_a
    :goto_4
    invoke-static {v7, v3}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V
    :try_end_3
    .catch Landroid/database/SQLException; {:try_start_3 .. :try_end_3} :catch_0

    .line 155
    .line 156
    .line 157
    goto :goto_6

    .line 158
    :goto_5
    invoke-static {p1, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 159
    .line 160
    .line 161
    :goto_6
    throw p2
.end method

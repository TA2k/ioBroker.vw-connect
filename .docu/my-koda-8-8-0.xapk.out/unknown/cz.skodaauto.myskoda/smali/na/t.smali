.class public final Lna/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:Lay0/a;

.field public final c:Ljava/util/concurrent/locks/ReentrantLock;

.field public d:I

.field public e:Z

.field public final f:[Lna/g;

.field public final g:Lez0/i;

.field public final h:Landroidx/collection/h;


# direct methods
.method public constructor <init>(ILay0/a;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lna/t;->a:I

    .line 5
    .line 6
    iput-object p2, p0, Lna/t;->b:Lay0/a;

    .line 7
    .line 8
    new-instance p2, Ljava/util/concurrent/locks/ReentrantLock;

    .line 9
    .line 10
    invoke-direct {p2}, Ljava/util/concurrent/locks/ReentrantLock;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lna/t;->c:Ljava/util/concurrent/locks/ReentrantLock;

    .line 14
    .line 15
    new-array p2, p1, [Lna/g;

    .line 16
    .line 17
    iput-object p2, p0, Lna/t;->f:[Lna/g;

    .line 18
    .line 19
    sget p2, Lez0/j;->a:I

    .line 20
    .line 21
    new-instance p2, Lez0/i;

    .line 22
    .line 23
    const/4 v0, 0x0

    .line 24
    invoke-direct {p2, p1, v0}, Lez0/h;-><init>(II)V

    .line 25
    .line 26
    .line 27
    iput-object p2, p0, Lna/t;->g:Lez0/i;

    .line 28
    .line 29
    new-instance p2, Landroidx/collection/h;

    .line 30
    .line 31
    invoke-direct {p2, v0}, Landroidx/collection/h;-><init>(I)V

    .line 32
    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    const/4 v1, 0x1

    .line 36
    if-lt p1, v1, :cond_2

    .line 37
    .line 38
    const/high16 v2, 0x40000000    # 2.0f

    .line 39
    .line 40
    if-gt p1, v2, :cond_1

    .line 41
    .line 42
    invoke-static {p1}, Ljava/lang/Integer;->bitCount(I)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eq v0, v1, :cond_0

    .line 47
    .line 48
    add-int/lit8 p1, p1, -0x1

    .line 49
    .line 50
    invoke-static {p1}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    shl-int/2addr p1, v1

    .line 55
    :cond_0
    add-int/lit8 v0, p1, -0x1

    .line 56
    .line 57
    iput v0, p2, Landroidx/collection/h;->g:I

    .line 58
    .line 59
    new-array p1, p1, [Ljava/lang/Object;

    .line 60
    .line 61
    iput-object p1, p2, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 62
    .line 63
    iput-object p2, p0, Lna/t;->h:Landroidx/collection/h;

    .line 64
    .line 65
    return-void

    .line 66
    :cond_1
    const-string p0, "capacity must be <= 2^30"

    .line 67
    .line 68
    invoke-static {p0}, La1/a;->c(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw v0

    .line 72
    :cond_2
    const-string p0, "capacity must be >= 1"

    .line 73
    .line 74
    invoke-static {p0}, La1/a;->c(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Lna/t;->h:Landroidx/collection/h;

    .line 2
    .line 3
    instance-of v1, p1, Lna/r;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lna/r;

    .line 9
    .line 10
    iget v2, v1, Lna/r;->f:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lna/r;->f:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lna/r;

    .line 23
    .line 24
    invoke-direct {v1, p0, p1}, Lna/r;-><init>(Lna/t;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lna/r;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lna/r;->f:I

    .line 32
    .line 33
    iget-object v4, p0, Lna/t;->g:Lez0/i;

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v3, :cond_2

    .line 37
    .line 38
    if-ne v3, v5, :cond_1

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iput v5, v1, Lna/r;->f:I

    .line 56
    .line 57
    invoke-virtual {v4, v1}, Lez0/h;->c(Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v2, :cond_3

    .line 62
    .line 63
    return-object v2

    .line 64
    :cond_3
    :goto_1
    :try_start_0
    iget-object p1, p0, Lna/t;->c:Ljava/util/concurrent/locks/ReentrantLock;

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    .line 68
    .line 69
    :try_start_1
    iget-boolean v1, p0, Lna/t;->e:Z

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    iget v1, v0, Landroidx/collection/h;->e:I

    .line 75
    .line 76
    iget v3, v0, Landroidx/collection/h;->f:I

    .line 77
    .line 78
    if-ne v1, v3, :cond_5

    .line 79
    .line 80
    iget v1, p0, Lna/t;->d:I

    .line 81
    .line 82
    iget v3, p0, Lna/t;->a:I

    .line 83
    .line 84
    if-lt v1, v3, :cond_4

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_4
    new-instance v1, Lna/g;

    .line 88
    .line 89
    iget-object v3, p0, Lna/t;->b:Lay0/a;

    .line 90
    .line 91
    invoke-interface {v3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    check-cast v3, Lua/a;

    .line 96
    .line 97
    invoke-direct {v1, v3}, Lna/g;-><init>(Lua/a;)V

    .line 98
    .line 99
    .line 100
    iget-object v3, p0, Lna/t;->f:[Lna/g;

    .line 101
    .line 102
    iget v6, p0, Lna/t;->d:I

    .line 103
    .line 104
    add-int/lit8 v7, v6, 0x1

    .line 105
    .line 106
    iput v7, p0, Lna/t;->d:I

    .line 107
    .line 108
    aput-object v1, v3, v6

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Landroidx/collection/h;->a(Lna/g;)V

    .line 111
    .line 112
    .line 113
    :cond_5
    :goto_2
    iget p0, v0, Landroidx/collection/h;->e:I

    .line 114
    .line 115
    iget v1, v0, Landroidx/collection/h;->f:I

    .line 116
    .line 117
    if-eq p0, v1, :cond_6

    .line 118
    .line 119
    iget-object v1, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v1, [Ljava/lang/Object;

    .line 122
    .line 123
    aget-object v3, v1, p0

    .line 124
    .line 125
    aput-object v2, v1, p0

    .line 126
    .line 127
    add-int/2addr p0, v5

    .line 128
    iget v1, v0, Landroidx/collection/h;->g:I

    .line 129
    .line 130
    and-int/2addr p0, v1

    .line 131
    iput p0, v0, Landroidx/collection/h;->e:I

    .line 132
    .line 133
    check-cast v3, Lna/g;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 134
    .line 135
    :try_start_2
    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 136
    .line 137
    .line 138
    return-object v3

    .line 139
    :catchall_0
    move-exception p0

    .line 140
    goto :goto_4

    .line 141
    :catchall_1
    move-exception p0

    .line 142
    goto :goto_3

    .line 143
    :cond_6
    :try_start_3
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 144
    .line 145
    invoke-direct {p0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>()V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_7
    const-string p0, "Connection pool is closed"

    .line 150
    .line 151
    const/16 v0, 0x15

    .line 152
    .line 153
    invoke-static {v0, p0}, Llp/k1;->e(ILjava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 157
    :goto_3
    :try_start_4
    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 158
    .line 159
    .line 160
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 161
    :goto_4
    invoke-virtual {v4}, Lez0/h;->f()V

    .line 162
    .line 163
    .line 164
    throw p0
.end method

.method public final b(JLc/d;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p4, Lna/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lna/s;

    .line 7
    .line 8
    iget v1, v0, Lna/s;->i:I

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
    iput v1, v0, Lna/s;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lna/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lna/s;-><init>(Lna/t;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lna/s;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lna/s;->i:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget-wide p1, v0, Lna/s;->d:J

    .line 38
    .line 39
    iget-object p3, v0, Lna/s;->f:Lkotlin/jvm/internal/f0;

    .line 40
    .line 41
    iget-object v2, v0, Lna/s;->e:Lay0/a;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    goto :goto_2

    .line 47
    :catchall_0
    move-exception p4

    .line 48
    goto :goto_4

    .line 49
    :cond_1
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
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :goto_1
    new-instance p4, Lkotlin/jvm/internal/f0;

    .line 61
    .line 62
    invoke-direct {p4}, Ljava/lang/Object;-><init>()V

    .line 63
    .line 64
    .line 65
    :try_start_1
    new-instance v2, Lk31/l;

    .line 66
    .line 67
    const/16 v5, 0x1b

    .line 68
    .line 69
    invoke-direct {v2, v5, p4, p0, v4}, Lk31/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 70
    .line 71
    .line 72
    iput-object p3, v0, Lna/s;->e:Lay0/a;

    .line 73
    .line 74
    iput-object p4, v0, Lna/s;->f:Lkotlin/jvm/internal/f0;

    .line 75
    .line 76
    iput-wide p1, v0, Lna/s;->d:J

    .line 77
    .line 78
    iput v3, v0, Lna/s;->i:I

    .line 79
    .line 80
    invoke-static {p1, p2}, Lvy0/e0;->O(J)J

    .line 81
    .line 82
    .line 83
    move-result-wide v5

    .line 84
    invoke-static {v5, v6, v2, v0}, Lvy0/e0;->S(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 88
    if-ne v2, v1, :cond_3

    .line 89
    .line 90
    return-object v1

    .line 91
    :cond_3
    move-object v2, p3

    .line 92
    move-object p3, p4

    .line 93
    :goto_2
    move-object p4, p3

    .line 94
    move-object p3, v2

    .line 95
    move-object v2, v0

    .line 96
    move-object v0, v4

    .line 97
    goto :goto_5

    .line 98
    :goto_3
    move-object v7, v2

    .line 99
    move-object v2, p3

    .line 100
    move-object p3, p4

    .line 101
    move-object p4, v7

    .line 102
    goto :goto_4

    .line 103
    :catchall_1
    move-exception v2

    .line 104
    goto :goto_3

    .line 105
    :goto_4
    move-object v7, p4

    .line 106
    move-object p4, p3

    .line 107
    move-object p3, v2

    .line 108
    move-object v2, v0

    .line 109
    move-object v0, v7

    .line 110
    :goto_5
    :try_start_2
    instance-of v5, v0, Lvy0/e2;

    .line 111
    .line 112
    if-eqz v5, :cond_4

    .line 113
    .line 114
    invoke-interface {p3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    goto :goto_6

    .line 118
    :catchall_2
    move-exception p1

    .line 119
    goto :goto_7

    .line 120
    :cond_4
    if-nez v0, :cond_6

    .line 121
    .line 122
    iget-object p4, p4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 123
    .line 124
    if-eqz p4, :cond_5

    .line 125
    .line 126
    return-object p4

    .line 127
    :cond_5
    :goto_6
    move-object v0, v2

    .line 128
    goto :goto_1

    .line 129
    :cond_6
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 130
    :goto_7
    iget-object p2, p4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast p2, Lna/g;

    .line 133
    .line 134
    if-eqz p2, :cond_7

    .line 135
    .line 136
    invoke-virtual {p0, p2}, Lna/t;->e(Lna/g;)V

    .line 137
    .line 138
    .line 139
    :cond_7
    throw p1
.end method

.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Lna/t;->c:Ljava/util/concurrent/locks/ReentrantLock;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    :try_start_0
    iput-boolean v1, p0, Lna/t;->e:Z

    .line 8
    .line 9
    iget-object p0, p0, Lna/t;->f:[Lna/g;

    .line 10
    .line 11
    array-length v1, p0

    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    if-ge v2, v1, :cond_1

    .line 14
    .line 15
    aget-object v3, p0, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    invoke-virtual {v3}, Lna/g;->close()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    .line 22
    goto :goto_1

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto :goto_2

    .line 25
    :cond_0
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :goto_2
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public final d(Ljava/lang/StringBuilder;)V
    .locals 12

    .line 1
    const-string v0, ", "

    .line 2
    .line 3
    iget-object v1, p0, Lna/t;->h:Landroidx/collection/h;

    .line 4
    .line 5
    iget-object v2, p0, Lna/t;->c:Ljava/util/concurrent/locks/ReentrantLock;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 8
    .line 9
    .line 10
    :try_start_0
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    iget v4, v1, Landroidx/collection/h;->f:I

    .line 15
    .line 16
    iget v5, v1, Landroidx/collection/h;->e:I

    .line 17
    .line 18
    sub-int/2addr v4, v5

    .line 19
    iget v5, v1, Landroidx/collection/h;->g:I

    .line 20
    .line 21
    and-int/2addr v4, v5

    .line 22
    const/4 v5, 0x0

    .line 23
    move v6, v5

    .line 24
    :goto_0
    if-ge v6, v4, :cond_1

    .line 25
    .line 26
    if-ltz v6, :cond_0

    .line 27
    .line 28
    iget v7, v1, Landroidx/collection/h;->f:I

    .line 29
    .line 30
    iget v8, v1, Landroidx/collection/h;->e:I

    .line 31
    .line 32
    sub-int/2addr v7, v8

    .line 33
    iget v9, v1, Landroidx/collection/h;->g:I

    .line 34
    .line 35
    and-int/2addr v7, v9

    .line 36
    if-ge v6, v7, :cond_0

    .line 37
    .line 38
    iget-object v7, v1, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v7, [Ljava/lang/Object;

    .line 41
    .line 42
    add-int/2addr v8, v6

    .line 43
    and-int/2addr v8, v9

    .line 44
    aget-object v7, v7, v8

    .line 45
    .line 46
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v3, v7}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    add-int/lit8 v6, v6, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :catchall_0
    move-exception v0

    .line 56
    move-object p0, v0

    .line 57
    goto/16 :goto_3

    .line 58
    .line 59
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 60
    .line 61
    invoke-direct {p0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>()V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_1
    invoke-static {v3}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    new-instance v1, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 72
    .line 73
    .line 74
    const/16 v3, 0x9

    .line 75
    .line 76
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v3, " ("

    .line 87
    .line 88
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    new-instance v1, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 101
    .line 102
    .line 103
    const-string v3, "capacity="

    .line 104
    .line 105
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget v3, p0, Lna/t;->a:I

    .line 109
    .line 110
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    new-instance v1, Ljava/lang/StringBuilder;

    .line 124
    .line 125
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 126
    .line 127
    .line 128
    const-string v3, "permits="

    .line 129
    .line 130
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    iget-object v3, p0, Lna/t;->g:Lez0/i;

    .line 134
    .line 135
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    sget-object v4, Lez0/h;->j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 139
    .line 140
    invoke-virtual {v4, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 141
    .line 142
    .line 143
    move-result v3

    .line 144
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 145
    .line 146
    .line 147
    move-result v3

    .line 148
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    new-instance v0, Ljava/lang/StringBuilder;

    .line 162
    .line 163
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 164
    .line 165
    .line 166
    const-string v1, "queue=(size="

    .line 167
    .line 168
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v6}, Lmx0/g;->c()I

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    const-string v1, ")["

    .line 179
    .line 180
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const/4 v10, 0x0

    .line 184
    const/16 v11, 0x3f

    .line 185
    .line 186
    const/4 v7, 0x0

    .line 187
    const/4 v8, 0x0

    .line 188
    const/4 v9, 0x0

    .line 189
    invoke-static/range {v6 .. v11}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    const/16 v1, 0x5d

    .line 197
    .line 198
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    const-string v0, ")"

    .line 209
    .line 210
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    const/16 v0, 0xa

    .line 214
    .line 215
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    iget-object p0, p0, Lna/t;->f:[Lna/g;

    .line 219
    .line 220
    array-length v1, p0

    .line 221
    move v3, v5

    .line 222
    :goto_1
    if-ge v5, v1, :cond_4

    .line 223
    .line 224
    aget-object v4, p0, v5

    .line 225
    .line 226
    add-int/lit8 v3, v3, 0x1

    .line 227
    .line 228
    new-instance v6, Ljava/lang/StringBuilder;

    .line 229
    .line 230
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 231
    .line 232
    .line 233
    const-string v7, "\t\t["

    .line 234
    .line 235
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    const-string v7, "] - "

    .line 242
    .line 243
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 244
    .line 245
    .line 246
    if-eqz v4, :cond_2

    .line 247
    .line 248
    iget-object v7, v4, Lna/g;->d:Lua/a;

    .line 249
    .line 250
    invoke-virtual {v7}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v7

    .line 254
    goto :goto_2

    .line 255
    :cond_2
    const/4 v7, 0x0

    .line 256
    :goto_2
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v6

    .line 263
    invoke-virtual {p1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 267
    .line 268
    .line 269
    if-eqz v4, :cond_3

    .line 270
    .line 271
    invoke-virtual {v4, p1}, Lna/g;->f(Ljava/lang/StringBuilder;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 272
    .line 273
    .line 274
    :cond_3
    add-int/lit8 v5, v5, 0x1

    .line 275
    .line 276
    goto :goto_1

    .line 277
    :cond_4
    invoke-virtual {v2}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 278
    .line 279
    .line 280
    return-void

    .line 281
    :goto_3
    invoke-virtual {v2}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 282
    .line 283
    .line 284
    throw p0
.end method

.method public final e(Lna/g;)V
    .locals 2

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lna/t;->c:Ljava/util/concurrent/locks/ReentrantLock;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 9
    .line 10
    .line 11
    :try_start_0
    iget-object v1, p0, Lna/t;->h:Landroidx/collection/h;

    .line 12
    .line 13
    invoke-virtual {v1, p1}, Landroidx/collection/h;->a(Lna/g;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lna/t;->g:Lez0/i;

    .line 20
    .line 21
    invoke-virtual {p0}, Lez0/h;->f()V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 27
    .line 28
    .line 29
    throw p0
.end method

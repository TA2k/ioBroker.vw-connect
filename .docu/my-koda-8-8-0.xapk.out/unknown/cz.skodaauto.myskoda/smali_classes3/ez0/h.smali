.class public Lez0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final synthetic h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final synthetic j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field private volatile synthetic _availablePermits$volatile:I

.field public final d:I

.field private volatile synthetic deqIdx$volatile:J

.field public final e:Lb50/c;

.field private volatile synthetic enqIdx$volatile:J

.field private volatile synthetic head$volatile:Ljava/lang/Object;

.field private volatile synthetic tail$volatile:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "head$volatile"

    .line 2
    .line 3
    const-class v1, Lez0/h;

    .line 4
    .line 5
    const-class v2, Ljava/lang/Object;

    .line 6
    .line 7
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lez0/h;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 12
    .line 13
    const-string v0, "deqIdx$volatile"

    .line 14
    .line 15
    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lez0/h;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 20
    .line 21
    const-string v0, "tail$volatile"

    .line 22
    .line 23
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Lez0/h;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 28
    .line 29
    const-string v0, "enqIdx$volatile"

    .line 30
    .line 31
    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lez0/h;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 36
    .line 37
    const-string v0, "_availablePermits$volatile"

    .line 38
    .line 39
    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lez0/h;->j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 44
    .line 45
    return-void
.end method

.method public constructor <init>(II)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lez0/h;->d:I

    .line 5
    .line 6
    if-lez p1, :cond_1

    .line 7
    .line 8
    if-ltz p2, :cond_0

    .line 9
    .line 10
    if-gt p2, p1, :cond_0

    .line 11
    .line 12
    new-instance v0, Lez0/k;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x2

    .line 16
    const-wide/16 v3, 0x0

    .line 17
    .line 18
    invoke-direct {v0, v3, v4, v1, v2}, Lez0/k;-><init>(JLez0/k;I)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lez0/h;->head$volatile:Ljava/lang/Object;

    .line 22
    .line 23
    iput-object v0, p0, Lez0/h;->tail$volatile:Ljava/lang/Object;

    .line 24
    .line 25
    sub-int/2addr p1, p2

    .line 26
    iput p1, p0, Lez0/h;->_availablePermits$volatile:I

    .line 27
    .line 28
    new-instance p1, Lb50/c;

    .line 29
    .line 30
    const/16 p2, 0xc

    .line 31
    .line 32
    invoke-direct {p1, p0, p2}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lez0/h;->e:Lb50/c;

    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    const-string p0, "The number of acquired permits should be in 0.."

    .line 39
    .line 40
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p1

    .line 54
    :cond_1
    const-string p0, "Semaphore should have at least 1 permit, but had "

    .line 55
    .line 56
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p1
.end method


# virtual methods
.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    :cond_0
    sget-object v0, Lez0/h;->j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->getAndDecrement(Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget v2, p0, Lez0/h;->d:I

    .line 8
    .line 9
    if-gt v1, v2, :cond_0

    .line 10
    .line 11
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    if-lez v1, :cond_1

    .line 14
    .line 15
    goto :goto_2

    .line 16
    :cond_1
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-static {p1}, Lvy0/e0;->x(Lkotlin/coroutines/Continuation;)Lvy0/l;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    :try_start_0
    invoke-virtual {p0, p1}, Lez0/h;->e(Lvy0/k2;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_4

    .line 29
    .line 30
    :cond_2
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->getAndDecrement(Ljava/lang/Object;)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-gt v1, v2, :cond_2

    .line 35
    .line 36
    if-lez v1, :cond_3

    .line 37
    .line 38
    iget-object p0, p0, Lez0/h;->e:Lb50/c;

    .line 39
    .line 40
    invoke-virtual {p1, v3, p0}, Lvy0/l;->t(Ljava/lang/Object;Lay0/o;)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_3
    invoke-virtual {p0, p1}, Lez0/h;->e(Lvy0/k2;)Z

    .line 45
    .line 46
    .line 47
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    if-eqz v1, :cond_2

    .line 49
    .line 50
    :cond_4
    :goto_0
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    if-ne p0, p1, :cond_5

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_5
    move-object p0, v3

    .line 60
    :goto_1
    if-ne p0, p1, :cond_6

    .line 61
    .line 62
    return-object p0

    .line 63
    :cond_6
    :goto_2
    return-object v3

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    invoke-virtual {p1}, Lvy0/l;->B()V

    .line 66
    .line 67
    .line 68
    throw p0
.end method

.method public final e(Lvy0/k2;)Z
    .locals 14

    .line 1
    sget-object v0, Lez0/h;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lez0/k;

    .line 8
    .line 9
    sget-object v2, Lez0/h;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 10
    .line 11
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    sget-object v4, Lez0/f;->d:Lez0/f;

    .line 16
    .line 17
    sget v5, Lez0/j;->f:I

    .line 18
    .line 19
    int-to-long v5, v5

    .line 20
    div-long v5, v2, v5

    .line 21
    .line 22
    :goto_0
    invoke-static {v1, v5, v6, v4}, Laz0/b;->b(Laz0/q;JLay0/n;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    invoke-static {v7}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v8

    .line 30
    if-nez v8, :cond_4

    .line 31
    .line 32
    invoke-static {v7}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    :cond_0
    :goto_1
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v9

    .line 40
    check-cast v9, Laz0/q;

    .line 41
    .line 42
    iget-wide v10, v9, Laz0/q;->f:J

    .line 43
    .line 44
    iget-wide v12, v8, Laz0/q;->f:J

    .line 45
    .line 46
    cmp-long v10, v10, v12

    .line 47
    .line 48
    if-ltz v10, :cond_1

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_1
    invoke-virtual {v8}, Laz0/q;->j()Z

    .line 52
    .line 53
    .line 54
    move-result v10

    .line 55
    if-nez v10, :cond_2

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    invoke-virtual {v0, p0, v9, v8}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v10

    .line 62
    if-eqz v10, :cond_3

    .line 63
    .line 64
    invoke-virtual {v9}, Laz0/q;->f()Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_4

    .line 69
    .line 70
    invoke-virtual {v9}, Laz0/c;->e()V

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v10

    .line 78
    if-eq v10, v9, :cond_2

    .line 79
    .line 80
    invoke-virtual {v8}, Laz0/q;->f()Z

    .line 81
    .line 82
    .line 83
    move-result v9

    .line 84
    if-eqz v9, :cond_0

    .line 85
    .line 86
    invoke-virtual {v8}, Laz0/c;->e()V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_4
    :goto_2
    invoke-static {v7}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    check-cast v0, Lez0/k;

    .line 95
    .line 96
    iget-object v1, v0, Lez0/k;->h:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 97
    .line 98
    sget v4, Lez0/j;->f:I

    .line 99
    .line 100
    int-to-long v4, v4

    .line 101
    rem-long/2addr v2, v4

    .line 102
    long-to-int v2, v2

    .line 103
    :cond_5
    const/4 v3, 0x0

    .line 104
    invoke-virtual {v1, v2, v3, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->compareAndSet(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    const/4 v4, 0x1

    .line 109
    if-eqz v3, :cond_6

    .line 110
    .line 111
    invoke-interface {p1, v0, v2}, Lvy0/k2;->b(Laz0/q;I)V

    .line 112
    .line 113
    .line 114
    return v4

    .line 115
    :cond_6
    invoke-virtual {v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    if-eqz v3, :cond_5

    .line 120
    .line 121
    sget-object v3, Lez0/j;->b:Lj51/i;

    .line 122
    .line 123
    sget-object v5, Lez0/j;->c:Lj51/i;

    .line 124
    .line 125
    :cond_7
    invoke-virtual {v1, v2, v3, v5}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->compareAndSet(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-eqz v0, :cond_8

    .line 130
    .line 131
    check-cast p1, Lvy0/k;

    .line 132
    .line 133
    iget-object p0, p0, Lez0/h;->e:Lb50/c;

    .line 134
    .line 135
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    invoke-interface {p1, v0, p0}, Lvy0/k;->t(Ljava/lang/Object;Lay0/o;)V

    .line 138
    .line 139
    .line 140
    return v4

    .line 141
    :cond_8
    invoke-virtual {v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    if-eq v0, v3, :cond_7

    .line 146
    .line 147
    const/4 p0, 0x0

    .line 148
    return p0
.end method

.method public final f()V
    .locals 14

    .line 1
    :cond_0
    sget-object v0, Lez0/h;->j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->getAndIncrement(Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget v2, p0, Lez0/h;->d:I

    .line 8
    .line 9
    if-ge v1, v2, :cond_11

    .line 10
    .line 11
    if-ltz v1, :cond_1

    .line 12
    .line 13
    goto/16 :goto_7

    .line 14
    .line 15
    :cond_1
    sget-object v0, Lez0/h;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Lez0/k;

    .line 22
    .line 23
    sget-object v2, Lez0/h;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 24
    .line 25
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 26
    .line 27
    .line 28
    move-result-wide v2

    .line 29
    sget v4, Lez0/j;->f:I

    .line 30
    .line 31
    int-to-long v4, v4

    .line 32
    div-long v4, v2, v4

    .line 33
    .line 34
    sget-object v6, Lez0/g;->d:Lez0/g;

    .line 35
    .line 36
    :goto_0
    invoke-static {v1, v4, v5, v6}, Laz0/b;->b(Laz0/q;JLay0/n;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    invoke-static {v7}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v8

    .line 44
    if-nez v8, :cond_6

    .line 45
    .line 46
    invoke-static {v7}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    :cond_2
    :goto_1
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v9

    .line 54
    check-cast v9, Laz0/q;

    .line 55
    .line 56
    iget-wide v10, v9, Laz0/q;->f:J

    .line 57
    .line 58
    iget-wide v12, v8, Laz0/q;->f:J

    .line 59
    .line 60
    cmp-long v10, v10, v12

    .line 61
    .line 62
    if-ltz v10, :cond_3

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    invoke-virtual {v8}, Laz0/q;->j()Z

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    if-nez v10, :cond_4

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_4
    invoke-virtual {v0, p0, v9, v8}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v10

    .line 76
    if-eqz v10, :cond_5

    .line 77
    .line 78
    invoke-virtual {v9}, Laz0/q;->f()Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_6

    .line 83
    .line 84
    invoke-virtual {v9}, Laz0/c;->e()V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_5
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v10

    .line 92
    if-eq v10, v9, :cond_4

    .line 93
    .line 94
    invoke-virtual {v8}, Laz0/q;->f()Z

    .line 95
    .line 96
    .line 97
    move-result v9

    .line 98
    if-eqz v9, :cond_2

    .line 99
    .line 100
    invoke-virtual {v8}, Laz0/c;->e()V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_6
    :goto_2
    invoke-static {v7}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    check-cast v0, Lez0/k;

    .line 109
    .line 110
    iget-object v1, v0, Lez0/k;->h:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 111
    .line 112
    invoke-virtual {v0}, Laz0/c;->b()V

    .line 113
    .line 114
    .line 115
    iget-wide v6, v0, Laz0/q;->f:J

    .line 116
    .line 117
    cmp-long v0, v6, v4

    .line 118
    .line 119
    const/4 v4, 0x0

    .line 120
    if-lez v0, :cond_7

    .line 121
    .line 122
    goto :goto_6

    .line 123
    :cond_7
    sget v0, Lez0/j;->f:I

    .line 124
    .line 125
    int-to-long v5, v0

    .line 126
    rem-long/2addr v2, v5

    .line 127
    long-to-int v0, v2

    .line 128
    sget-object v2, Lez0/j;->b:Lj51/i;

    .line 129
    .line 130
    invoke-virtual {v1, v0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->getAndSet(ILjava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    const/4 v3, 0x1

    .line 135
    if-nez v2, :cond_c

    .line 136
    .line 137
    sget v2, Lez0/j;->a:I

    .line 138
    .line 139
    move v5, v4

    .line 140
    :goto_3
    if-ge v5, v2, :cond_9

    .line 141
    .line 142
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    sget-object v7, Lez0/j;->c:Lj51/i;

    .line 147
    .line 148
    if-ne v6, v7, :cond_8

    .line 149
    .line 150
    :goto_4
    move v4, v3

    .line 151
    goto :goto_6

    .line 152
    :cond_8
    add-int/lit8 v5, v5, 0x1

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_9
    sget-object v5, Lez0/j;->b:Lj51/i;

    .line 156
    .line 157
    sget-object v6, Lez0/j;->d:Lj51/i;

    .line 158
    .line 159
    :cond_a
    invoke-virtual {v1, v0, v5, v6}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->compareAndSet(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    if-eqz v2, :cond_b

    .line 164
    .line 165
    move v4, v3

    .line 166
    goto :goto_5

    .line 167
    :cond_b
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    if-eq v2, v5, :cond_a

    .line 172
    .line 173
    :goto_5
    xor-int/2addr v4, v3

    .line 174
    goto :goto_6

    .line 175
    :cond_c
    sget-object v0, Lez0/j;->e:Lj51/i;

    .line 176
    .line 177
    if-ne v2, v0, :cond_d

    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_d
    instance-of v0, v2, Lvy0/k;

    .line 181
    .line 182
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 183
    .line 184
    if-eqz v0, :cond_e

    .line 185
    .line 186
    check-cast v2, Lvy0/k;

    .line 187
    .line 188
    iget-object v0, p0, Lez0/h;->e:Lb50/c;

    .line 189
    .line 190
    invoke-interface {v2, v1, v0}, Lvy0/k;->h(Ljava/lang/Object;Lay0/o;)Lj51/i;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    if-eqz v0, :cond_f

    .line 195
    .line 196
    invoke-interface {v2, v0}, Lvy0/k;->w(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    goto :goto_4

    .line 200
    :cond_e
    instance-of v0, v2, Ldz0/f;

    .line 201
    .line 202
    if-eqz v0, :cond_10

    .line 203
    .line 204
    check-cast v2, Ldz0/f;

    .line 205
    .line 206
    check-cast v2, Ldz0/e;

    .line 207
    .line 208
    invoke-virtual {v2, p0, v1}, Ldz0/e;->h(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 209
    .line 210
    .line 211
    move-result v0

    .line 212
    if-nez v0, :cond_f

    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_f
    :goto_6
    if-eqz v4, :cond_0

    .line 216
    .line 217
    :goto_7
    return-void

    .line 218
    :cond_10
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 219
    .line 220
    new-instance v0, Ljava/lang/StringBuilder;

    .line 221
    .line 222
    const-string v1, "unexpected: "

    .line 223
    .line 224
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 228
    .line 229
    .line 230
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    throw p0

    .line 242
    :cond_11
    :goto_8
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 243
    .line 244
    .line 245
    move-result v1

    .line 246
    if-le v1, v2, :cond_12

    .line 247
    .line 248
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    .line 249
    .line 250
    .line 251
    move-result v1

    .line 252
    if-nez v1, :cond_12

    .line 253
    .line 254
    goto :goto_8

    .line 255
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 256
    .line 257
    new-instance v0, Ljava/lang/StringBuilder;

    .line 258
    .line 259
    const-string v1, "The number of released permits cannot be greater than "

    .line 260
    .line 261
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    throw p0
.end method

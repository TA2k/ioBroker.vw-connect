.class public Lxy0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxy0/n;


# static fields
.field public static final synthetic e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final synthetic f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final synthetic g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final synthetic h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final synthetic i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic l:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic m:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field private volatile synthetic _closeCause$volatile:Ljava/lang/Object;

.field private volatile synthetic bufferEnd$volatile:J

.field private volatile synthetic bufferEndSegment$volatile:Ljava/lang/Object;

.field private volatile synthetic closeHandler$volatile:Ljava/lang/Object;

.field private volatile synthetic completedExpandBuffersAndPauseFlag$volatile:J

.field public final d:I

.field private volatile synthetic receiveSegment$volatile:Ljava/lang/Object;

.field private volatile synthetic receivers$volatile:J

.field private volatile synthetic sendSegment$volatile:Ljava/lang/Object;

.field private volatile synthetic sendersAndCloseStatus$volatile:J


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "sendersAndCloseStatus$volatile"

    .line 2
    .line 3
    const-class v1, Lxy0/j;

    .line 4
    .line 5
    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 10
    .line 11
    const-string v0, "receivers$volatile"

    .line 12
    .line 13
    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 18
    .line 19
    const-string v0, "bufferEnd$volatile"

    .line 20
    .line 21
    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 26
    .line 27
    const-string v0, "completedExpandBuffersAndPauseFlag$volatile"

    .line 28
    .line 29
    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lxy0/j;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 34
    .line 35
    const-string v0, "sendSegment$volatile"

    .line 36
    .line 37
    const-class v2, Ljava/lang/Object;

    .line 38
    .line 39
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lxy0/j;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 44
    .line 45
    const-string v0, "receiveSegment$volatile"

    .line 46
    .line 47
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 52
    .line 53
    const-string v0, "bufferEndSegment$volatile"

    .line 54
    .line 55
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sput-object v0, Lxy0/j;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 60
    .line 61
    const-string v0, "_closeCause$volatile"

    .line 62
    .line 63
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    sput-object v0, Lxy0/j;->l:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 68
    .line 69
    const-string v0, "closeHandler$volatile"

    .line 70
    .line 71
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    sput-object v0, Lxy0/j;->m:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 76
    .line 77
    return-void
.end method

.method public constructor <init>(I)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxy0/j;->d:I

    .line 5
    .line 6
    if-ltz p1, :cond_3

    .line 7
    .line 8
    sget-object v0, Lxy0/l;->a:Lxy0/r;

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    const v0, 0x7fffffff

    .line 13
    .line 14
    .line 15
    if-eq p1, v0, :cond_0

    .line 16
    .line 17
    int-to-long v0, p1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const-wide v0, 0x7fffffffffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const-wide/16 v0, 0x0

    .line 26
    .line 27
    :goto_0
    iput-wide v0, p0, Lxy0/j;->bufferEnd$volatile:J

    .line 28
    .line 29
    sget-object p1, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 30
    .line 31
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 32
    .line 33
    .line 34
    move-result-wide v0

    .line 35
    iput-wide v0, p0, Lxy0/j;->completedExpandBuffersAndPauseFlag$volatile:J

    .line 36
    .line 37
    new-instance v2, Lxy0/r;

    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    const/4 v7, 0x3

    .line 41
    const-wide/16 v3, 0x0

    .line 42
    .line 43
    move-object v6, p0

    .line 44
    invoke-direct/range {v2 .. v7}, Lxy0/r;-><init>(JLxy0/r;Lxy0/j;I)V

    .line 45
    .line 46
    .line 47
    iput-object v2, v6, Lxy0/j;->sendSegment$volatile:Ljava/lang/Object;

    .line 48
    .line 49
    iput-object v2, v6, Lxy0/j;->receiveSegment$volatile:Ljava/lang/Object;

    .line 50
    .line 51
    invoke-virtual {v6}, Lxy0/j;->D()Z

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    if-eqz p0, :cond_2

    .line 56
    .line 57
    sget-object v2, Lxy0/l;->a:Lxy0/r;

    .line 58
    .line 59
    const-string p0, "null cannot be cast to non-null type kotlinx.coroutines.channels.ChannelSegment<E of kotlinx.coroutines.channels.BufferedChannel>"

    .line 60
    .line 61
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    :cond_2
    iput-object v2, v6, Lxy0/j;->bufferEndSegment$volatile:Ljava/lang/Object;

    .line 65
    .line 66
    sget-object p0, Lxy0/l;->s:Lj51/i;

    .line 67
    .line 68
    iput-object p0, v6, Lxy0/j;->_closeCause$volatile:Ljava/lang/Object;

    .line 69
    .line 70
    return-void

    .line 71
    :cond_3
    const-string p0, "Invalid channel capacity: "

    .line 72
    .line 73
    const-string v0, ", should be >=0"

    .line 74
    .line 75
    invoke-static {p0, p1, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p1
.end method

.method public static G(Lxy0/j;Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p1, Lxy0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lxy0/h;

    .line 7
    .line 8
    iget v1, v0, Lxy0/h;->f:I

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
    iput v1, v0, Lxy0/h;->f:I

    .line 18
    .line 19
    :goto_0
    move-object v6, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lxy0/h;

    .line 22
    .line 23
    invoke-direct {v0, p0, p1}, Lxy0/h;-><init>(Lxy0/j;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object p1, v6, Lxy0/h;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v1, v6, Lxy0/h;->f:I

    .line 32
    .line 33
    const/4 v2, 0x1

    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    if-ne v1, v2, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    check-cast p1, Lxy0/q;

    .line 42
    .line 43
    iget-object p0, p1, Lxy0/q;->a:Ljava/lang/Object;

    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    sget-object p1, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 58
    .line 59
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    check-cast p1, Lxy0/r;

    .line 64
    .line 65
    :goto_2
    invoke-virtual {p0}, Lxy0/j;->A()Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_3

    .line 70
    .line 71
    invoke-virtual {p0}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    new-instance p1, Lxy0/o;

    .line 76
    .line 77
    invoke-direct {p1, p0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 78
    .line 79
    .line 80
    return-object p1

    .line 81
    :cond_3
    sget-object v1, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 82
    .line 83
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 84
    .line 85
    .line 86
    move-result-wide v4

    .line 87
    sget v1, Lxy0/l;->b:I

    .line 88
    .line 89
    int-to-long v7, v1

    .line 90
    div-long v9, v4, v7

    .line 91
    .line 92
    rem-long v7, v4, v7

    .line 93
    .line 94
    long-to-int v3, v7

    .line 95
    iget-wide v7, p1, Laz0/q;->f:J

    .line 96
    .line 97
    cmp-long v1, v7, v9

    .line 98
    .line 99
    if-eqz v1, :cond_5

    .line 100
    .line 101
    invoke-virtual {p0, v9, v10, p1}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    if-nez v1, :cond_4

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_4
    move-object v8, v1

    .line 109
    goto :goto_3

    .line 110
    :cond_5
    move-object v8, p1

    .line 111
    :goto_3
    const/4 v12, 0x0

    .line 112
    move-object v7, p0

    .line 113
    move v9, v3

    .line 114
    move-wide v10, v4

    .line 115
    invoke-virtual/range {v7 .. v12}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    move-object v1, v7

    .line 120
    sget-object p1, Lxy0/l;->m:Lj51/i;

    .line 121
    .line 122
    if-eq p0, p1, :cond_a

    .line 123
    .line 124
    sget-object p1, Lxy0/l;->o:Lj51/i;

    .line 125
    .line 126
    if-ne p0, p1, :cond_7

    .line 127
    .line 128
    invoke-virtual {v1}, Lxy0/j;->w()J

    .line 129
    .line 130
    .line 131
    move-result-wide p0

    .line 132
    cmp-long p0, v4, p0

    .line 133
    .line 134
    if-gez p0, :cond_6

    .line 135
    .line 136
    invoke-virtual {v8}, Laz0/c;->b()V

    .line 137
    .line 138
    .line 139
    :cond_6
    move-object p0, v1

    .line 140
    move-object p1, v8

    .line 141
    goto :goto_2

    .line 142
    :cond_7
    sget-object p1, Lxy0/l;->n:Lj51/i;

    .line 143
    .line 144
    if-ne p0, p1, :cond_9

    .line 145
    .line 146
    iput v2, v6, Lxy0/h;->f:I

    .line 147
    .line 148
    move-object v2, v8

    .line 149
    invoke-virtual/range {v1 .. v6}, Lxy0/j;->H(Lxy0/r;IJLrx0/c;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    if-ne p0, v0, :cond_8

    .line 154
    .line 155
    return-object v0

    .line 156
    :cond_8
    return-object p0

    .line 157
    :cond_9
    invoke-virtual {v8}, Laz0/c;->b()V

    .line 158
    .line 159
    .line 160
    return-object p0

    .line 161
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 162
    .line 163
    const-string p1, "unexpected"

    .line 164
    .line 165
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw p0
.end method

.method public static final a(Lxy0/j;JLxy0/r;)Lxy0/r;
    .locals 11

    .line 1
    sget-object v0, Lxy0/l;->a:Lxy0/r;

    .line 2
    .line 3
    sget-object v0, Lxy0/k;->d:Lxy0/k;

    .line 4
    .line 5
    :goto_0
    invoke-static {p3, p1, p2, v0}, Laz0/b;->b(Laz0/q;JLay0/n;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v1}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-nez v2, :cond_4

    .line 14
    .line 15
    invoke-static {v1}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    :cond_0
    :goto_1
    sget-object v3, Lxy0/j;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 20
    .line 21
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    check-cast v4, Laz0/q;

    .line 26
    .line 27
    iget-wide v5, v4, Laz0/q;->f:J

    .line 28
    .line 29
    iget-wide v7, v2, Laz0/q;->f:J

    .line 30
    .line 31
    cmp-long v5, v5, v7

    .line 32
    .line 33
    if-ltz v5, :cond_1

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_1
    invoke-virtual {v2}, Laz0/q;->j()Z

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-nez v5, :cond_2

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-virtual {v3, p0, v4, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    if-eqz v5, :cond_3

    .line 48
    .line 49
    invoke-virtual {v4}, Laz0/q;->f()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_4

    .line 54
    .line 55
    invoke-virtual {v4}, Laz0/c;->e()V

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    if-eq v5, v4, :cond_2

    .line 64
    .line 65
    invoke-virtual {v2}, Laz0/q;->f()Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-eqz v3, :cond_0

    .line 70
    .line 71
    invoke-virtual {v2}, Laz0/c;->e()V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_4
    :goto_2
    invoke-static {v1}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    const/4 v2, 0x0

    .line 80
    sget-object v3, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 81
    .line 82
    if-eqz v0, :cond_5

    .line 83
    .line 84
    invoke-virtual {p0}, Lxy0/j;->B()Z

    .line 85
    .line 86
    .line 87
    iget-wide p1, p3, Laz0/q;->f:J

    .line 88
    .line 89
    sget v0, Lxy0/l;->b:I

    .line 90
    .line 91
    int-to-long v0, v0

    .line 92
    mul-long/2addr p1, v0

    .line 93
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 94
    .line 95
    .line 96
    move-result-wide v0

    .line 97
    cmp-long p0, p1, v0

    .line 98
    .line 99
    if-gez p0, :cond_7

    .line 100
    .line 101
    invoke-virtual {p3}, Laz0/c;->b()V

    .line 102
    .line 103
    .line 104
    return-object v2

    .line 105
    :cond_5
    invoke-static {v1}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 106
    .line 107
    .line 108
    move-result-object p3

    .line 109
    check-cast p3, Lxy0/r;

    .line 110
    .line 111
    iget-wide v0, p3, Laz0/q;->f:J

    .line 112
    .line 113
    cmp-long p1, v0, p1

    .line 114
    .line 115
    if-lez p1, :cond_9

    .line 116
    .line 117
    sget p1, Lxy0/l;->b:I

    .line 118
    .line 119
    int-to-long p1, p1

    .line 120
    mul-long/2addr p1, v0

    .line 121
    :goto_3
    sget-object v4, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 122
    .line 123
    invoke-virtual {v4, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 124
    .line 125
    .line 126
    move-result-wide v7

    .line 127
    const-wide v4, 0xfffffffffffffffL

    .line 128
    .line 129
    .line 130
    .line 131
    .line 132
    and-long/2addr v4, v7

    .line 133
    cmp-long v6, v4, p1

    .line 134
    .line 135
    if-ltz v6, :cond_6

    .line 136
    .line 137
    move-object v6, p0

    .line 138
    goto :goto_4

    .line 139
    :cond_6
    const/16 v6, 0x3c

    .line 140
    .line 141
    shr-long v9, v7, v6

    .line 142
    .line 143
    long-to-int v9, v9

    .line 144
    int-to-long v9, v9

    .line 145
    shl-long/2addr v9, v6

    .line 146
    add-long/2addr v9, v4

    .line 147
    sget-object v5, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 148
    .line 149
    move-object v6, p0

    .line 150
    invoke-virtual/range {v5 .. v10}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    if-eqz p0, :cond_8

    .line 155
    .line 156
    :goto_4
    sget p0, Lxy0/l;->b:I

    .line 157
    .line 158
    int-to-long p0, p0

    .line 159
    mul-long/2addr v0, p0

    .line 160
    invoke-virtual {v3, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 161
    .line 162
    .line 163
    move-result-wide p0

    .line 164
    cmp-long p0, v0, p0

    .line 165
    .line 166
    if-gez p0, :cond_7

    .line 167
    .line 168
    invoke-virtual {p3}, Laz0/c;->b()V

    .line 169
    .line 170
    .line 171
    :cond_7
    return-object v2

    .line 172
    :cond_8
    move-object p0, v6

    .line 173
    goto :goto_3

    .line 174
    :cond_9
    return-object p3
.end method

.method public static final b(Lxy0/j;Ljava/lang/Object;Lvy0/l;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lxy0/j;->v()Ljava/lang/Throwable;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p2, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public static final c(Lxy0/j;Ldz0/f;)V
    .locals 9

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 5
    .line 6
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lxy0/r;

    .line 11
    .line 12
    :goto_0
    invoke-virtual {p0}, Lxy0/j;->A()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    sget-object p0, Lxy0/l;->l:Lj51/i;

    .line 19
    .line 20
    check-cast p1, Ldz0/e;

    .line 21
    .line 22
    iput-object p0, p1, Ldz0/e;->h:Ljava/lang/Object;

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    sget-object v1, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 26
    .line 27
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 28
    .line 29
    .line 30
    move-result-wide v5

    .line 31
    sget v1, Lxy0/l;->b:I

    .line 32
    .line 33
    int-to-long v1, v1

    .line 34
    div-long v3, v5, v1

    .line 35
    .line 36
    rem-long v1, v5, v1

    .line 37
    .line 38
    long-to-int v1, v1

    .line 39
    iget-wide v7, v0, Laz0/q;->f:J

    .line 40
    .line 41
    cmp-long v2, v7, v3

    .line 42
    .line 43
    if-eqz v2, :cond_2

    .line 44
    .line 45
    invoke-virtual {p0, v3, v4, v0}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    if-nez v2, :cond_1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    move-object v3, v2

    .line 53
    move-object v7, p1

    .line 54
    move v4, v1

    .line 55
    move-object v2, p0

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    move-object v3, v0

    .line 58
    move-object v2, p0

    .line 59
    move-object v7, p1

    .line 60
    move v4, v1

    .line 61
    :goto_1
    invoke-virtual/range {v2 .. v7}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    move-object v0, v3

    .line 66
    sget-object p1, Lxy0/l;->m:Lj51/i;

    .line 67
    .line 68
    if-ne p0, p1, :cond_5

    .line 69
    .line 70
    instance-of p0, v7, Lvy0/k2;

    .line 71
    .line 72
    if-eqz p0, :cond_3

    .line 73
    .line 74
    move-object p1, v7

    .line 75
    check-cast p1, Lvy0/k2;

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
    const/4 p1, 0x0

    .line 79
    :goto_2
    if-eqz p1, :cond_4

    .line 80
    .line 81
    invoke-interface {p1, v0, v4}, Lvy0/k2;->b(Laz0/q;I)V

    .line 82
    .line 83
    .line 84
    :cond_4
    return-void

    .line 85
    :cond_5
    sget-object p1, Lxy0/l;->o:Lj51/i;

    .line 86
    .line 87
    if-ne p0, p1, :cond_7

    .line 88
    .line 89
    invoke-virtual {v2}, Lxy0/j;->w()J

    .line 90
    .line 91
    .line 92
    move-result-wide p0

    .line 93
    cmp-long p0, v5, p0

    .line 94
    .line 95
    if-gez p0, :cond_6

    .line 96
    .line 97
    invoke-virtual {v0}, Laz0/c;->b()V

    .line 98
    .line 99
    .line 100
    :cond_6
    move-object p0, v2

    .line 101
    move-object p1, v7

    .line 102
    goto :goto_0

    .line 103
    :cond_7
    sget-object p1, Lxy0/l;->n:Lj51/i;

    .line 104
    .line 105
    if-eq p0, p1, :cond_8

    .line 106
    .line 107
    invoke-virtual {v0}, Laz0/c;->b()V

    .line 108
    .line 109
    .line 110
    move-object p1, v7

    .line 111
    check-cast p1, Ldz0/e;

    .line 112
    .line 113
    iput-object p0, p1, Ldz0/e;->h:Ljava/lang/Object;

    .line 114
    .line 115
    return-void

    .line 116
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 117
    .line 118
    const-string p1, "unexpected"

    .line 119
    .line 120
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0
.end method

.method public static final f(Lxy0/j;Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I
    .locals 4

    .line 1
    invoke-virtual {p1, p2, p3}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    if-eqz p7, :cond_0

    .line 5
    .line 6
    invoke-virtual/range {p0 .. p7}, Lxy0/j;->M(Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :cond_0
    invoke-virtual {p1, p2}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x1

    .line 16
    const/4 v2, 0x0

    .line 17
    if-nez v0, :cond_3

    .line 18
    .line 19
    invoke-virtual {p0, p4, p5}, Lxy0/j;->g(J)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    sget-object v0, Lxy0/l;->d:Lj51/i;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v2, v0}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_6

    .line 32
    .line 33
    return v1

    .line 34
    :cond_1
    if-nez p6, :cond_2

    .line 35
    .line 36
    const/4 p0, 0x3

    .line 37
    return p0

    .line 38
    :cond_2
    invoke-virtual {p1, p2, v2, p6}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_6

    .line 43
    .line 44
    const/4 p0, 0x2

    .line 45
    return p0

    .line 46
    :cond_3
    instance-of v3, v0, Lvy0/k2;

    .line 47
    .line 48
    if-eqz v3, :cond_6

    .line 49
    .line 50
    invoke-virtual {p1, p2, v2}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v0, p3}, Lxy0/j;->J(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-eqz p0, :cond_4

    .line 58
    .line 59
    sget-object p0, Lxy0/l;->i:Lj51/i;

    .line 60
    .line 61
    invoke-virtual {p1, p2, p0}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x0

    .line 65
    return p0

    .line 66
    :cond_4
    sget-object p0, Lxy0/l;->k:Lj51/i;

    .line 67
    .line 68
    iget-object p3, p1, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 69
    .line 70
    mul-int/lit8 p4, p2, 0x2

    .line 71
    .line 72
    add-int/2addr p4, v1

    .line 73
    invoke-virtual {p3, p4, p0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->getAndSet(ILjava/lang/Object;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    if-eq p3, p0, :cond_5

    .line 78
    .line 79
    invoke-virtual {p1, p2, v1}, Lxy0/r;->m(IZ)V

    .line 80
    .line 81
    .line 82
    :cond_5
    const/4 p0, 0x5

    .line 83
    return p0

    .line 84
    :cond_6
    invoke-virtual/range {p0 .. p7}, Lxy0/j;->M(Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    return p0
.end method

.method public static y(Lxy0/j;)V
    .locals 7

    .line 1
    sget-object v0, Lxy0/j;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    const-wide/16 v1, 0x1

    .line 4
    .line 5
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->addAndGet(Ljava/lang/Object;J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    const-wide/high16 v3, 0x4000000000000000L    # 2.0

    .line 10
    .line 11
    and-long/2addr v1, v3

    .line 12
    const-wide/16 v5, 0x0

    .line 13
    .line 14
    cmp-long v1, v1, v5

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    :goto_0
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 19
    .line 20
    .line 21
    move-result-wide v1

    .line 22
    and-long/2addr v1, v3

    .line 23
    cmp-long v1, v1, v5

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    return-void
.end method


# virtual methods
.method public final A()Z
    .locals 3

    .line 1
    sget-object v0, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-virtual {p0, v0, v1, v2}, Lxy0/j;->z(JZ)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final B()Z
    .locals 3

    .line 1
    sget-object v0, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-virtual {p0, v0, v1, v2}, Lxy0/j;->z(JZ)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public C()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final D()Z
    .locals 4

    .line 1
    sget-object v0, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    cmp-long p0, v0, v2

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    const-wide v2, 0x7fffffffffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    cmp-long p0, v0, v2

    .line 19
    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    return p0

    .line 25
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 26
    return p0
.end method

.method public final E(JLxy0/r;)V
    .locals 4

    .line 1
    :goto_0
    iget-wide v0, p3, Laz0/q;->f:J

    .line 2
    .line 3
    cmp-long v0, v0, p1

    .line 4
    .line 5
    if-gez v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p3}, Laz0/c;->c()Laz0/c;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lxy0/r;

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    move-object p3, v0

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    :goto_1
    invoke-virtual {p3}, Laz0/q;->d()Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-eqz p1, :cond_3

    .line 23
    .line 24
    invoke-virtual {p3}, Laz0/c;->c()Laz0/c;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Lxy0/r;

    .line 29
    .line 30
    if-nez p1, :cond_2

    .line 31
    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move-object p3, p1

    .line 34
    goto :goto_1

    .line 35
    :cond_3
    :goto_2
    sget-object p1, Lxy0/j;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 36
    .line 37
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    check-cast p2, Laz0/q;

    .line 42
    .line 43
    iget-wide v0, p2, Laz0/q;->f:J

    .line 44
    .line 45
    iget-wide v2, p3, Laz0/q;->f:J

    .line 46
    .line 47
    cmp-long v0, v0, v2

    .line 48
    .line 49
    if-ltz v0, :cond_4

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_4
    invoke-virtual {p3}, Laz0/q;->j()Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-nez v0, :cond_5

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_5
    invoke-virtual {p1, p0, p2, p3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_7

    .line 64
    .line 65
    invoke-virtual {p2}, Laz0/q;->f()Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    if-eqz p0, :cond_6

    .line 70
    .line 71
    invoke-virtual {p2}, Laz0/c;->e()V

    .line 72
    .line 73
    .line 74
    :cond_6
    :goto_3
    return-void

    .line 75
    :cond_7
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    if-eq v0, p2, :cond_5

    .line 80
    .line 81
    invoke-virtual {p3}, Laz0/q;->f()Z

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    if-eqz p1, :cond_3

    .line 86
    .line 87
    invoke-virtual {p3}, Laz0/c;->e()V

    .line 88
    .line 89
    .line 90
    goto :goto_2
.end method

.method public final F(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p1, Lvy0/l;

    .line 2
    .line 3
    invoke-static {p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    const/4 v0, 0x1

    .line 8
    invoke-direct {p1, v0, p2}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Lvy0/l;->q()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lxy0/j;->v()Ljava/lang/Throwable;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {p1, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    if-ne p0, p1, :cond_0

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method

.method public final H(Lxy0/r;IJLrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p5, Lxy0/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p5

    .line 6
    check-cast v0, Lxy0/i;

    .line 7
    .line 8
    iget v1, v0, Lxy0/i;->f:I

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
    iput v1, v0, Lxy0/i;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxy0/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p5}, Lxy0/i;-><init>(Lxy0/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p5, v0, Lxy0/i;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxy0/i;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto/16 :goto_6

    .line 40
    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iput v3, v0, Lxy0/i;->f:I

    .line 53
    .line 54
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 55
    .line 56
    .line 57
    move-result-object p5

    .line 58
    invoke-static {p5}, Lvy0/e0;->x(Lkotlin/coroutines/Continuation;)Lvy0/l;

    .line 59
    .line 60
    .line 61
    move-result-object p5

    .line 62
    :try_start_0
    new-instance v7, Lxy0/y;

    .line 63
    .line 64
    invoke-direct {v7, p5}, Lxy0/y;-><init>(Lvy0/l;)V

    .line 65
    .line 66
    .line 67
    move-object v2, p0

    .line 68
    move-object v3, p1

    .line 69
    move v4, p2

    .line 70
    move-wide v5, p3

    .line 71
    invoke-virtual/range {v2 .. v7}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    sget-object p1, Lxy0/l;->m:Lj51/i;

    .line 76
    .line 77
    if-ne p0, p1, :cond_3

    .line 78
    .line 79
    invoke-virtual {v7, v3, v4}, Lxy0/y;->b(Laz0/q;I)V

    .line 80
    .line 81
    .line 82
    goto/16 :goto_5

    .line 83
    .line 84
    :catchall_0
    move-exception v0

    .line 85
    move-object p0, v0

    .line 86
    goto/16 :goto_7

    .line 87
    .line 88
    :cond_3
    sget-object p1, Lxy0/l;->o:Lj51/i;

    .line 89
    .line 90
    const/4 p2, 0x0

    .line 91
    if-ne p0, p1, :cond_c

    .line 92
    .line 93
    invoke-virtual {v2}, Lxy0/j;->w()J

    .line 94
    .line 95
    .line 96
    move-result-wide p0

    .line 97
    cmp-long p0, v5, p0

    .line 98
    .line 99
    if-gez p0, :cond_4

    .line 100
    .line 101
    invoke-virtual {v3}, Laz0/c;->b()V

    .line 102
    .line 103
    .line 104
    :cond_4
    sget-object p0, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 105
    .line 106
    invoke-virtual {p0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    check-cast p0, Lxy0/r;

    .line 111
    .line 112
    :goto_1
    invoke-virtual {v2}, Lxy0/j;->A()Z

    .line 113
    .line 114
    .line 115
    move-result p1

    .line 116
    if-eqz p1, :cond_5

    .line 117
    .line 118
    invoke-virtual {v2}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    new-instance p1, Lxy0/o;

    .line 123
    .line 124
    invoke-direct {p1, p0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 125
    .line 126
    .line 127
    new-instance p0, Lxy0/q;

    .line 128
    .line 129
    invoke-direct {p0, p1}, Lxy0/q;-><init>(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p5, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    goto :goto_5

    .line 136
    :cond_5
    sget-object p1, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 137
    .line 138
    invoke-virtual {p1, v2}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 139
    .line 140
    .line 141
    move-result-wide v5

    .line 142
    sget p1, Lxy0/l;->b:I

    .line 143
    .line 144
    int-to-long p3, p1

    .line 145
    div-long v3, v5, p3

    .line 146
    .line 147
    rem-long p3, v5, p3

    .line 148
    .line 149
    long-to-int p1, p3

    .line 150
    iget-wide p3, p0, Laz0/q;->f:J

    .line 151
    .line 152
    cmp-long p3, p3, v3

    .line 153
    .line 154
    if-eqz p3, :cond_7

    .line 155
    .line 156
    invoke-virtual {v2, v3, v4, p0}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 157
    .line 158
    .line 159
    move-result-object p3

    .line 160
    if-nez p3, :cond_6

    .line 161
    .line 162
    goto :goto_1

    .line 163
    :cond_6
    move-object v3, p3

    .line 164
    :goto_2
    move v4, p1

    .line 165
    goto :goto_3

    .line 166
    :cond_7
    move-object v3, p0

    .line 167
    goto :goto_2

    .line 168
    :goto_3
    invoke-virtual/range {v2 .. v7}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    move-object p3, v3

    .line 173
    sget-object p1, Lxy0/l;->m:Lj51/i;

    .line 174
    .line 175
    if-ne p0, p1, :cond_8

    .line 176
    .line 177
    invoke-virtual {v7, p3, v4}, Lxy0/y;->b(Laz0/q;I)V

    .line 178
    .line 179
    .line 180
    goto :goto_5

    .line 181
    :cond_8
    sget-object p1, Lxy0/l;->o:Lj51/i;

    .line 182
    .line 183
    if-ne p0, p1, :cond_a

    .line 184
    .line 185
    invoke-virtual {v2}, Lxy0/j;->w()J

    .line 186
    .line 187
    .line 188
    move-result-wide p0

    .line 189
    cmp-long p0, v5, p0

    .line 190
    .line 191
    if-gez p0, :cond_9

    .line 192
    .line 193
    invoke-virtual {p3}, Laz0/c;->b()V

    .line 194
    .line 195
    .line 196
    :cond_9
    move-object p0, p3

    .line 197
    goto :goto_1

    .line 198
    :cond_a
    sget-object p1, Lxy0/l;->n:Lj51/i;

    .line 199
    .line 200
    if-eq p0, p1, :cond_b

    .line 201
    .line 202
    invoke-virtual {p3}, Laz0/c;->b()V

    .line 203
    .line 204
    .line 205
    new-instance p1, Lxy0/q;

    .line 206
    .line 207
    invoke-direct {p1, p0}, Lxy0/q;-><init>(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    goto :goto_4

    .line 211
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 212
    .line 213
    const-string p1, "unexpected"

    .line 214
    .line 215
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    throw p0

    .line 219
    :cond_c
    invoke-virtual {v3}, Laz0/c;->b()V

    .line 220
    .line 221
    .line 222
    new-instance p1, Lxy0/q;

    .line 223
    .line 224
    invoke-direct {p1, p0}, Lxy0/q;-><init>(Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    :goto_4
    invoke-virtual {p5, p1, p2}, Lvy0/l;->t(Ljava/lang/Object;Lay0/o;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 228
    .line 229
    .line 230
    :goto_5
    invoke-virtual {p5}, Lvy0/l;->p()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p5

    .line 234
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 235
    .line 236
    if-ne p5, v1, :cond_d

    .line 237
    .line 238
    return-object v1

    .line 239
    :cond_d
    :goto_6
    check-cast p5, Lxy0/q;

    .line 240
    .line 241
    iget-object p0, p5, Lxy0/q;->a:Ljava/lang/Object;

    .line 242
    .line 243
    return-object p0

    .line 244
    :goto_7
    invoke-virtual {p5}, Lvy0/l;->B()V

    .line 245
    .line 246
    .line 247
    throw p0
.end method

.method public final I(Lvy0/k2;Z)V
    .locals 1

    .line 1
    instance-of v0, p1, Lvy0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    if-eqz p2, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lxy0/j;->t()Ljava/lang/Throwable;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lxy0/j;->v()Ljava/lang/Throwable;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-interface {p1, p0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    instance-of p2, p1, Lxy0/y;

    .line 27
    .line 28
    if-eqz p2, :cond_2

    .line 29
    .line 30
    check-cast p1, Lxy0/y;

    .line 31
    .line 32
    iget-object p1, p1, Lxy0/y;->d:Lvy0/l;

    .line 33
    .line 34
    invoke-virtual {p0}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    new-instance p2, Lxy0/o;

    .line 39
    .line 40
    invoke-direct {p2, p0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 41
    .line 42
    .line 43
    new-instance p0, Lxy0/q;

    .line 44
    .line 45
    invoke-direct {p0, p2}, Lxy0/q;-><init>(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_2
    instance-of p2, p1, Lxy0/c;

    .line 53
    .line 54
    if-eqz p2, :cond_4

    .line 55
    .line 56
    check-cast p1, Lxy0/c;

    .line 57
    .line 58
    iget-object p0, p1, Lxy0/c;->e:Lvy0/l;

    .line 59
    .line 60
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    const/4 p2, 0x0

    .line 64
    iput-object p2, p1, Lxy0/c;->e:Lvy0/l;

    .line 65
    .line 66
    sget-object p2, Lxy0/l;->l:Lj51/i;

    .line 67
    .line 68
    iput-object p2, p1, Lxy0/c;->d:Ljava/lang/Object;

    .line 69
    .line 70
    iget-object p1, p1, Lxy0/c;->f:Lxy0/j;

    .line 71
    .line 72
    invoke-virtual {p1}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    if-nez p1, :cond_3

    .line 77
    .line 78
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 79
    .line 80
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_3
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_4
    instance-of p2, p1, Ldz0/f;

    .line 93
    .line 94
    if-eqz p2, :cond_5

    .line 95
    .line 96
    check-cast p1, Ldz0/f;

    .line 97
    .line 98
    sget-object p2, Lxy0/l;->l:Lj51/i;

    .line 99
    .line 100
    check-cast p1, Ldz0/e;

    .line 101
    .line 102
    invoke-virtual {p1, p0, p2}, Ldz0/e;->h(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 103
    .line 104
    .line 105
    return-void

    .line 106
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 107
    .line 108
    new-instance p2, Ljava/lang/StringBuilder;

    .line 109
    .line 110
    const-string v0, "Unexpected waiter: "

    .line 111
    .line 112
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw p0
.end method

.method public final J(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ldz0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    check-cast p1, Ldz0/f;

    .line 6
    .line 7
    check-cast p1, Ldz0/e;

    .line 8
    .line 9
    invoke-virtual {p1, p0, p2}, Ldz0/e;->h(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0

    .line 19
    :cond_1
    instance-of p0, p1, Lxy0/y;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    if-eqz p0, :cond_2

    .line 23
    .line 24
    check-cast p1, Lxy0/y;

    .line 25
    .line 26
    iget-object p0, p1, Lxy0/y;->d:Lvy0/l;

    .line 27
    .line 28
    new-instance p1, Lxy0/q;

    .line 29
    .line 30
    invoke-direct {p1, p2}, Lxy0/q;-><init>(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-static {p0, p1, v0}, Lxy0/l;->a(Lvy0/k;Ljava/lang/Object;Lay0/o;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    return p0

    .line 38
    :cond_2
    instance-of p0, p1, Lxy0/c;

    .line 39
    .line 40
    if-eqz p0, :cond_3

    .line 41
    .line 42
    check-cast p1, Lxy0/c;

    .line 43
    .line 44
    iget-object p0, p1, Lxy0/c;->e:Lvy0/l;

    .line 45
    .line 46
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iput-object v0, p1, Lxy0/c;->e:Lvy0/l;

    .line 50
    .line 51
    iput-object p2, p1, Lxy0/c;->d:Ljava/lang/Object;

    .line 52
    .line 53
    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 54
    .line 55
    iget-object p1, p1, Lxy0/c;->f:Lxy0/j;

    .line 56
    .line 57
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-static {p0, p2, v0}, Lxy0/l;->a(Lvy0/k;Ljava/lang/Object;Lay0/o;)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    return p0

    .line 65
    :cond_3
    instance-of p0, p1, Lvy0/k;

    .line 66
    .line 67
    if-eqz p0, :cond_4

    .line 68
    .line 69
    check-cast p1, Lvy0/k;

    .line 70
    .line 71
    invoke-static {p1, p2, v0}, Lxy0/l;->a(Lvy0/k;Ljava/lang/Object;Lay0/o;)Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    return p0

    .line 76
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    new-instance p2, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    const-string v0, "Unexpected receiver type: "

    .line 81
    .line 82
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0
.end method

.method public final K(Ljava/lang/Object;Lxy0/r;I)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lvy0/k;

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    check-cast p1, Lvy0/k;

    .line 9
    .line 10
    invoke-static {p1, v1, v2}, Lxy0/l;->a(Lvy0/k;Ljava/lang/Object;Lay0/o;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :cond_0
    instance-of v0, p1, Ldz0/f;

    .line 16
    .line 17
    if-eqz v0, :cond_7

    .line 18
    .line 19
    check-cast p1, Ldz0/e;

    .line 20
    .line 21
    invoke-virtual {p1, p0, v1}, Ldz0/e;->h(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    const/4 p1, 0x1

    .line 26
    if-eqz p0, :cond_4

    .line 27
    .line 28
    if-eq p0, p1, :cond_3

    .line 29
    .line 30
    const/4 v0, 0x2

    .line 31
    if-eq p0, v0, :cond_2

    .line 32
    .line 33
    const/4 v0, 0x3

    .line 34
    if-ne p0, v0, :cond_1

    .line 35
    .line 36
    sget-object p0, Ldz0/i;->g:Ldz0/i;

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 40
    .line 41
    new-instance p2, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    const-string p3, "Unexpected internal result: "

    .line 44
    .line 45
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p1

    .line 63
    :cond_2
    sget-object p0, Ldz0/i;->f:Ldz0/i;

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    sget-object p0, Ldz0/i;->e:Ldz0/i;

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_4
    sget-object p0, Ldz0/i;->d:Ldz0/i;

    .line 70
    .line 71
    :goto_0
    sget-object v0, Ldz0/i;->e:Ldz0/i;

    .line 72
    .line 73
    if-ne p0, v0, :cond_5

    .line 74
    .line 75
    invoke-virtual {p2, p3, v2}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :cond_5
    sget-object p2, Ldz0/i;->d:Ldz0/i;

    .line 79
    .line 80
    if-ne p0, p2, :cond_6

    .line 81
    .line 82
    return p1

    .line 83
    :cond_6
    const/4 p0, 0x0

    .line 84
    return p0

    .line 85
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    new-instance p2, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string p3, "Unexpected waiter: "

    .line 90
    .line 91
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0
.end method

.method public final L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p1, p2}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p1, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const-wide v3, 0xfffffffffffffffL

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    sget-object v5, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {v5, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v6

    .line 21
    and-long/2addr v6, v3

    .line 22
    cmp-long v6, p3, v6

    .line 23
    .line 24
    if-ltz v6, :cond_2

    .line 25
    .line 26
    if-nez p5, :cond_0

    .line 27
    .line 28
    sget-object p0, Lxy0/l;->n:Lj51/i;

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_0
    invoke-virtual {p1, p2, v0, p5}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 38
    .line 39
    .line 40
    sget-object p0, Lxy0/l;->m:Lj51/i;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_1
    sget-object v6, Lxy0/l;->d:Lj51/i;

    .line 44
    .line 45
    if-ne v0, v6, :cond_2

    .line 46
    .line 47
    sget-object v6, Lxy0/l;->i:Lj51/i;

    .line 48
    .line 49
    invoke-virtual {p1, p2, v0, v6}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_2

    .line 54
    .line 55
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 56
    .line 57
    .line 58
    mul-int/lit8 p0, p2, 0x2

    .line 59
    .line 60
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {p1, p2, v2}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    return-object p0

    .line 68
    :cond_2
    invoke-virtual {p1, p2}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    if-eqz v0, :cond_b

    .line 73
    .line 74
    sget-object v6, Lxy0/l;->e:Lj51/i;

    .line 75
    .line 76
    if-ne v0, v6, :cond_3

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_3
    sget-object v6, Lxy0/l;->d:Lj51/i;

    .line 80
    .line 81
    if-ne v0, v6, :cond_4

    .line 82
    .line 83
    sget-object v6, Lxy0/l;->i:Lj51/i;

    .line 84
    .line 85
    invoke-virtual {p1, p2, v0, v6}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-eqz v0, :cond_2

    .line 90
    .line 91
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 92
    .line 93
    .line 94
    mul-int/lit8 p0, p2, 0x2

    .line 95
    .line 96
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-virtual {p1, p2, v2}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    return-object p0

    .line 104
    :cond_4
    sget-object v6, Lxy0/l;->j:Lj51/i;

    .line 105
    .line 106
    if-ne v0, v6, :cond_5

    .line 107
    .line 108
    sget-object p0, Lxy0/l;->o:Lj51/i;

    .line 109
    .line 110
    return-object p0

    .line 111
    :cond_5
    sget-object v7, Lxy0/l;->h:Lj51/i;

    .line 112
    .line 113
    if-ne v0, v7, :cond_6

    .line 114
    .line 115
    sget-object p0, Lxy0/l;->o:Lj51/i;

    .line 116
    .line 117
    return-object p0

    .line 118
    :cond_6
    sget-object v7, Lxy0/l;->l:Lj51/i;

    .line 119
    .line 120
    if-ne v0, v7, :cond_7

    .line 121
    .line 122
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 123
    .line 124
    .line 125
    sget-object p0, Lxy0/l;->o:Lj51/i;

    .line 126
    .line 127
    return-object p0

    .line 128
    :cond_7
    sget-object v7, Lxy0/l;->g:Lj51/i;

    .line 129
    .line 130
    if-eq v0, v7, :cond_2

    .line 131
    .line 132
    sget-object v7, Lxy0/l;->f:Lj51/i;

    .line 133
    .line 134
    invoke-virtual {p1, p2, v0, v7}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v7

    .line 138
    if-eqz v7, :cond_2

    .line 139
    .line 140
    instance-of p3, v0, Lxy0/b0;

    .line 141
    .line 142
    if-eqz p3, :cond_8

    .line 143
    .line 144
    check-cast v0, Lxy0/b0;

    .line 145
    .line 146
    iget-object v0, v0, Lxy0/b0;->a:Lvy0/k2;

    .line 147
    .line 148
    :cond_8
    invoke-virtual {p0, v0, p1, p2}, Lxy0/j;->K(Ljava/lang/Object;Lxy0/r;I)Z

    .line 149
    .line 150
    .line 151
    move-result p4

    .line 152
    if-eqz p4, :cond_9

    .line 153
    .line 154
    sget-object p3, Lxy0/l;->i:Lj51/i;

    .line 155
    .line 156
    invoke-virtual {p1, p2, p3}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 160
    .line 161
    .line 162
    mul-int/lit8 p0, p2, 0x2

    .line 163
    .line 164
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    invoke-virtual {p1, p2, v2}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    return-object p0

    .line 172
    :cond_9
    invoke-virtual {p1, p2, v6}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p1}, Laz0/q;->i()V

    .line 176
    .line 177
    .line 178
    if-eqz p3, :cond_a

    .line 179
    .line 180
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 181
    .line 182
    .line 183
    :cond_a
    sget-object p0, Lxy0/l;->o:Lj51/i;

    .line 184
    .line 185
    return-object p0

    .line 186
    :cond_b
    :goto_0
    invoke-virtual {v5, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 187
    .line 188
    .line 189
    move-result-wide v6

    .line 190
    and-long/2addr v6, v3

    .line 191
    cmp-long v6, p3, v6

    .line 192
    .line 193
    if-gez v6, :cond_c

    .line 194
    .line 195
    sget-object v6, Lxy0/l;->h:Lj51/i;

    .line 196
    .line 197
    invoke-virtual {p1, p2, v0, v6}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v0

    .line 201
    if-eqz v0, :cond_2

    .line 202
    .line 203
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 204
    .line 205
    .line 206
    sget-object p0, Lxy0/l;->o:Lj51/i;

    .line 207
    .line 208
    return-object p0

    .line 209
    :cond_c
    if-nez p5, :cond_d

    .line 210
    .line 211
    sget-object p0, Lxy0/l;->n:Lj51/i;

    .line 212
    .line 213
    return-object p0

    .line 214
    :cond_d
    invoke-virtual {p1, p2, v0, p5}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v0

    .line 218
    if-eqz v0, :cond_2

    .line 219
    .line 220
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 221
    .line 222
    .line 223
    sget-object p0, Lxy0/l;->m:Lj51/i;

    .line 224
    .line 225
    return-object p0
.end method

.method public final M(Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I
    .locals 5

    .line 1
    :cond_0
    invoke-virtual {p1, p2}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x4

    .line 6
    const/4 v2, 0x1

    .line 7
    const/4 v3, 0x0

    .line 8
    if-nez v0, :cond_4

    .line 9
    .line 10
    invoke-virtual {p0, p4, p5}, Lxy0/j;->g(J)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    if-nez p7, :cond_1

    .line 17
    .line 18
    sget-object v0, Lxy0/l;->d:Lj51/i;

    .line 19
    .line 20
    invoke-virtual {p1, p2, v3, v0}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    if-eqz p7, :cond_2

    .line 28
    .line 29
    sget-object v0, Lxy0/l;->j:Lj51/i;

    .line 30
    .line 31
    invoke-virtual {p1, p2, v3, v0}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-virtual {p1}, Laz0/q;->i()V

    .line 38
    .line 39
    .line 40
    return v1

    .line 41
    :cond_2
    if-nez p6, :cond_3

    .line 42
    .line 43
    const/4 p0, 0x3

    .line 44
    return p0

    .line 45
    :cond_3
    invoke-virtual {p1, p2, v3, p6}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_0

    .line 50
    .line 51
    const/4 p0, 0x2

    .line 52
    return p0

    .line 53
    :cond_4
    sget-object v4, Lxy0/l;->e:Lj51/i;

    .line 54
    .line 55
    if-ne v0, v4, :cond_5

    .line 56
    .line 57
    sget-object v1, Lxy0/l;->d:Lj51/i;

    .line 58
    .line 59
    invoke-virtual {p1, p2, v0, v1}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_0

    .line 64
    .line 65
    :goto_0
    return v2

    .line 66
    :cond_5
    sget-object p4, Lxy0/l;->k:Lj51/i;

    .line 67
    .line 68
    const/4 p5, 0x5

    .line 69
    if-ne v0, p4, :cond_6

    .line 70
    .line 71
    invoke-virtual {p1, p2, v3}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    return p5

    .line 75
    :cond_6
    sget-object p6, Lxy0/l;->h:Lj51/i;

    .line 76
    .line 77
    if-ne v0, p6, :cond_7

    .line 78
    .line 79
    invoke-virtual {p1, p2, v3}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    return p5

    .line 83
    :cond_7
    sget-object p6, Lxy0/l;->l:Lj51/i;

    .line 84
    .line 85
    if-ne v0, p6, :cond_8

    .line 86
    .line 87
    invoke-virtual {p1, p2, v3}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0}, Lxy0/j;->B()Z

    .line 91
    .line 92
    .line 93
    return v1

    .line 94
    :cond_8
    invoke-virtual {p1, p2, v3}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    instance-of p6, v0, Lxy0/b0;

    .line 98
    .line 99
    if-eqz p6, :cond_9

    .line 100
    .line 101
    check-cast v0, Lxy0/b0;

    .line 102
    .line 103
    iget-object v0, v0, Lxy0/b0;->a:Lvy0/k2;

    .line 104
    .line 105
    :cond_9
    invoke-virtual {p0, v0, p3}, Lxy0/j;->J(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    if-eqz p0, :cond_a

    .line 110
    .line 111
    sget-object p0, Lxy0/l;->i:Lj51/i;

    .line 112
    .line 113
    invoke-virtual {p1, p2, p0}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    const/4 p0, 0x0

    .line 117
    return p0

    .line 118
    :cond_a
    iget-object p0, p1, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 119
    .line 120
    mul-int/lit8 p3, p2, 0x2

    .line 121
    .line 122
    add-int/2addr p3, v2

    .line 123
    invoke-virtual {p0, p3, p4}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->getAndSet(ILjava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    if-eq p0, p4, :cond_b

    .line 128
    .line 129
    invoke-virtual {p1, p2, v2}, Lxy0/r;->m(IZ)V

    .line 130
    .line 131
    .line 132
    :cond_b
    return p5
.end method

.method public final N(J)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    invoke-virtual {v1}, Lxy0/j;->D()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_6

    .line 10
    .line 11
    :cond_0
    :goto_0
    sget-object v6, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 12
    .line 13
    invoke-virtual {v6, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    cmp-long v0, v2, p1

    .line 18
    .line 19
    if-lez v0, :cond_8

    .line 20
    .line 21
    sget v0, Lxy0/l;->c:I

    .line 22
    .line 23
    const/4 v7, 0x0

    .line 24
    move v2, v7

    .line 25
    :goto_1
    sget-object v3, Lxy0/j;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 26
    .line 27
    const-wide v8, 0x3fffffffffffffffL    # 1.9999999999999998

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    if-ge v2, v0, :cond_2

    .line 33
    .line 34
    invoke-virtual {v6, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 35
    .line 36
    .line 37
    move-result-wide v4

    .line 38
    invoke-virtual {v3, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 39
    .line 40
    .line 41
    move-result-wide v10

    .line 42
    and-long/2addr v8, v10

    .line 43
    cmp-long v3, v4, v8

    .line 44
    .line 45
    if-nez v3, :cond_1

    .line 46
    .line 47
    invoke-virtual {v6, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 48
    .line 49
    .line 50
    move-result-wide v8

    .line 51
    cmp-long v3, v4, v8

    .line 52
    .line 53
    if-nez v3, :cond_1

    .line 54
    .line 55
    goto :goto_6

    .line 56
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    move-object v0, v3

    .line 60
    :goto_2
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 61
    .line 62
    .line 63
    move-result-wide v2

    .line 64
    and-long v4, v2, v8

    .line 65
    .line 66
    const-wide/high16 v10, 0x4000000000000000L    # 2.0

    .line 67
    .line 68
    add-long/2addr v4, v10

    .line 69
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_7

    .line 74
    .line 75
    :goto_3
    invoke-virtual {v6, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 76
    .line 77
    .line 78
    move-result-wide v2

    .line 79
    move-wide v4, v2

    .line 80
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 81
    .line 82
    .line 83
    move-result-wide v2

    .line 84
    and-long v12, v2, v8

    .line 85
    .line 86
    and-long v14, v2, v10

    .line 87
    .line 88
    const-wide/16 v16, 0x0

    .line 89
    .line 90
    cmp-long v14, v14, v16

    .line 91
    .line 92
    if-eqz v14, :cond_3

    .line 93
    .line 94
    const/4 v14, 0x1

    .line 95
    goto :goto_4

    .line 96
    :cond_3
    move v14, v7

    .line 97
    :goto_4
    cmp-long v15, v4, v12

    .line 98
    .line 99
    if-nez v15, :cond_5

    .line 100
    .line 101
    invoke-virtual {v6, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 102
    .line 103
    .line 104
    move-result-wide v15

    .line 105
    cmp-long v4, v4, v15

    .line 106
    .line 107
    if-nez v4, :cond_5

    .line 108
    .line 109
    :goto_5
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 110
    .line 111
    .line 112
    move-result-wide v2

    .line 113
    and-long v4, v2, v8

    .line 114
    .line 115
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    if-eqz v2, :cond_4

    .line 120
    .line 121
    :goto_6
    return-void

    .line 122
    :cond_4
    move-object/from16 v1, p0

    .line 123
    .line 124
    goto :goto_5

    .line 125
    :cond_5
    if-nez v14, :cond_6

    .line 126
    .line 127
    add-long v4, v10, v12

    .line 128
    .line 129
    move-object/from16 v1, p0

    .line 130
    .line 131
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 132
    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_6
    move-object/from16 v1, p0

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_7
    move-object/from16 v1, p0

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_8
    move-object/from16 v1, p0

    .line 142
    .line 143
    goto/16 :goto_0
.end method

.method public final d(Ljava/util/concurrent/CancellationException;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    new-instance p1, Ljava/util/concurrent/CancellationException;

    .line 4
    .line 5
    const-string v0, "Channel was cancelled"

    .line 6
    .line 7
    invoke-direct {p1, v0}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    const/4 v0, 0x1

    .line 11
    invoke-virtual {p0, p1, v0}, Lxy0/j;->j(Ljava/lang/Throwable;Z)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public e(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 15

    .line 1
    sget-object v8, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v8, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    const/4 v9, 0x0

    .line 8
    invoke-virtual {p0, v1, v2, v9}, Lxy0/j;->z(JZ)Z

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    const/4 v10, 0x1

    .line 13
    const-wide v11, 0xfffffffffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    move v1, v9

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    and-long/2addr v1, v11

    .line 23
    invoke-virtual {p0, v1, v2}, Lxy0/j;->g(J)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    xor-int/2addr v1, v10

    .line 28
    :goto_0
    sget-object v13, Lxy0/q;->b:Lxy0/p;

    .line 29
    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    return-object v13

    .line 33
    :cond_1
    sget-object v6, Lxy0/l;->j:Lj51/i;

    .line 34
    .line 35
    sget-object v1, Lxy0/j;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 36
    .line 37
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Lxy0/r;

    .line 42
    .line 43
    :goto_1
    invoke-virtual {v8, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 44
    .line 45
    .line 46
    move-result-wide v2

    .line 47
    and-long v4, v2, v11

    .line 48
    .line 49
    invoke-virtual {p0, v2, v3, v9}, Lxy0/j;->z(JZ)Z

    .line 50
    .line 51
    .line 52
    move-result v7

    .line 53
    sget v14, Lxy0/l;->b:I

    .line 54
    .line 55
    int-to-long v2, v14

    .line 56
    div-long v11, v4, v2

    .line 57
    .line 58
    rem-long v2, v4, v2

    .line 59
    .line 60
    long-to-int v2, v2

    .line 61
    iget-wide v9, v1, Laz0/q;->f:J

    .line 62
    .line 63
    cmp-long v3, v9, v11

    .line 64
    .line 65
    if-eqz v3, :cond_4

    .line 66
    .line 67
    invoke-static {p0, v11, v12, v1}, Lxy0/j;->a(Lxy0/j;JLxy0/r;)Lxy0/r;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    if-nez v3, :cond_3

    .line 72
    .line 73
    if-eqz v7, :cond_2

    .line 74
    .line 75
    invoke-virtual {p0}, Lxy0/j;->v()Ljava/lang/Throwable;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    new-instance v1, Lxy0/o;

    .line 80
    .line 81
    invoke-direct {v1, v0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    return-object v1

    .line 85
    :cond_2
    const/4 v9, 0x0

    .line 86
    const/4 v10, 0x1

    .line 87
    :goto_2
    const-wide v11, 0xfffffffffffffffL

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    move-object v1, v3

    .line 94
    :cond_4
    move-object v0, p0

    .line 95
    move-object/from16 v3, p1

    .line 96
    .line 97
    invoke-static/range {v0 .. v7}, Lxy0/j;->f(Lxy0/j;Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I

    .line 98
    .line 99
    .line 100
    move-result v9

    .line 101
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    if-eqz v9, :cond_e

    .line 104
    .line 105
    const/4 v10, 0x1

    .line 106
    if-eq v9, v10, :cond_d

    .line 107
    .line 108
    const/4 v3, 0x2

    .line 109
    if-eq v9, v3, :cond_9

    .line 110
    .line 111
    const/4 v2, 0x3

    .line 112
    if-eq v9, v2, :cond_8

    .line 113
    .line 114
    const/4 v2, 0x4

    .line 115
    if-eq v9, v2, :cond_6

    .line 116
    .line 117
    const/4 v2, 0x5

    .line 118
    if-eq v9, v2, :cond_5

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_5
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 122
    .line 123
    .line 124
    :goto_3
    const/4 v9, 0x0

    .line 125
    goto :goto_2

    .line 126
    :cond_6
    sget-object v2, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 127
    .line 128
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 129
    .line 130
    .line 131
    move-result-wide v2

    .line 132
    cmp-long v2, v4, v2

    .line 133
    .line 134
    if-gez v2, :cond_7

    .line 135
    .line 136
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 137
    .line 138
    .line 139
    :cond_7
    invoke-virtual {p0}, Lxy0/j;->v()Ljava/lang/Throwable;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    new-instance v1, Lxy0/o;

    .line 144
    .line 145
    invoke-direct {v1, v0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 146
    .line 147
    .line 148
    return-object v1

    .line 149
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    const-string v1, "unexpected"

    .line 152
    .line 153
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw v0

    .line 157
    :cond_9
    if-eqz v7, :cond_a

    .line 158
    .line 159
    invoke-virtual {v1}, Laz0/q;->i()V

    .line 160
    .line 161
    .line 162
    invoke-virtual {p0}, Lxy0/j;->v()Ljava/lang/Throwable;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    new-instance v1, Lxy0/o;

    .line 167
    .line 168
    invoke-direct {v1, v0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 169
    .line 170
    .line 171
    return-object v1

    .line 172
    :cond_a
    instance-of v0, v6, Lvy0/k2;

    .line 173
    .line 174
    if-eqz v0, :cond_b

    .line 175
    .line 176
    check-cast v6, Lvy0/k2;

    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_b
    const/4 v6, 0x0

    .line 180
    :goto_4
    if-eqz v6, :cond_c

    .line 181
    .line 182
    add-int/2addr v2, v14

    .line 183
    invoke-interface {v6, v1, v2}, Lvy0/k2;->b(Laz0/q;I)V

    .line 184
    .line 185
    .line 186
    :cond_c
    invoke-virtual {v1}, Laz0/q;->i()V

    .line 187
    .line 188
    .line 189
    return-object v13

    .line 190
    :cond_d
    return-object v3

    .line 191
    :cond_e
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 192
    .line 193
    .line 194
    return-object v3
.end method

.method public final g(J)Z
    .locals 4

    .line 1
    sget-object v0, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    cmp-long v0, p1, v0

    .line 8
    .line 9
    if-ltz v0, :cond_1

    .line 10
    .line 11
    sget-object v0, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    iget p0, p0, Lxy0/j;->d:I

    .line 18
    .line 19
    int-to-long v2, p0

    .line 20
    add-long/2addr v0, v2

    .line 21
    cmp-long p0, p1, v0

    .line 22
    .line 23
    if-gez p0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 29
    return p0
.end method

.method public final h(Ljava/lang/Throwable;)Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Lxy0/j;->j(Ljava/lang/Throwable;Z)Z

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public final i()Lcom/google/firebase/messaging/w;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    sget-object v2, Lxy0/d;->d:Lxy0/d;

    .line 4
    .line 5
    const/4 v1, 0x3

    .line 6
    invoke-static {v1, v2}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    sget-object v3, Lxy0/e;->d:Lxy0/e;

    .line 10
    .line 11
    invoke-static {v1, v3}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/16 v5, 0x9

    .line 16
    .line 17
    move-object v1, p0

    .line 18
    invoke-direct/range {v0 .. v5}, Lcom/google/firebase/messaging/w;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method

.method public final isEmpty()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lxy0/j;->A()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    invoke-virtual {p0}, Lxy0/j;->x()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    return v1

    .line 16
    :cond_1
    invoke-virtual {p0}, Lxy0/j;->A()Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    xor-int/lit8 p0, p0, 0x1

    .line 21
    .line 22
    return p0
.end method

.method public final iterator()Lxy0/c;
    .locals 1

    .line 1
    new-instance v0, Lxy0/c;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lxy0/c;-><init>(Lxy0/j;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final j(Ljava/lang/Throwable;Z)Z
    .locals 12

    .line 1
    const/16 v0, 0x3c

    .line 2
    .line 3
    const-wide v1, 0xfffffffffffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    sget-object v3, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 9
    .line 10
    const/4 v9, 0x1

    .line 11
    if-eqz p2, :cond_1

    .line 12
    .line 13
    :goto_0
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v5

    .line 17
    shr-long v7, v5, v0

    .line 18
    .line 19
    long-to-int v4, v7

    .line 20
    if-nez v4, :cond_1

    .line 21
    .line 22
    and-long v7, v5, v1

    .line 23
    .line 24
    sget-object v4, Lxy0/l;->a:Lxy0/r;

    .line 25
    .line 26
    int-to-long v10, v9

    .line 27
    shl-long/2addr v10, v0

    .line 28
    add-long/2addr v7, v10

    .line 29
    move-object v4, p0

    .line 30
    invoke-virtual/range {v3 .. v8}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_0

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_0
    move-object p0, v4

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    move-object v4, p0

    .line 40
    :goto_1
    sget-object p0, Lxy0/l;->s:Lj51/i;

    .line 41
    .line 42
    :cond_2
    sget-object v5, Lxy0/j;->l:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 43
    .line 44
    invoke-virtual {v5, v4, p0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    if-eqz v6, :cond_3

    .line 49
    .line 50
    move v10, v9

    .line 51
    goto :goto_2

    .line 52
    :cond_3
    invoke-virtual {v5, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    if-eq v5, p0, :cond_2

    .line 57
    .line 58
    const/4 p0, 0x0

    .line 59
    move v10, p0

    .line 60
    :goto_2
    const/4 v11, 0x3

    .line 61
    if-eqz p2, :cond_5

    .line 62
    .line 63
    :cond_4
    invoke-virtual {v3, v4}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 64
    .line 65
    .line 66
    move-result-wide v5

    .line 67
    and-long p0, v5, v1

    .line 68
    .line 69
    int-to-long v7, v11

    .line 70
    shl-long/2addr v7, v0

    .line 71
    add-long/2addr v7, p0

    .line 72
    invoke-virtual/range {v3 .. v8}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-eqz p0, :cond_4

    .line 77
    .line 78
    goto :goto_5

    .line 79
    :cond_5
    invoke-virtual {v3, v4}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 80
    .line 81
    .line 82
    move-result-wide v5

    .line 83
    shr-long p0, v5, v0

    .line 84
    .line 85
    long-to-int p0, p0

    .line 86
    if-eqz p0, :cond_7

    .line 87
    .line 88
    if-eq p0, v9, :cond_6

    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_6
    and-long p0, v5, v1

    .line 92
    .line 93
    int-to-long v7, v11

    .line 94
    :goto_3
    shl-long/2addr v7, v0

    .line 95
    add-long/2addr v7, p0

    .line 96
    goto :goto_4

    .line 97
    :cond_7
    and-long p0, v5, v1

    .line 98
    .line 99
    const/4 p2, 0x2

    .line 100
    int-to-long v7, p2

    .line 101
    goto :goto_3

    .line 102
    :goto_4
    invoke-virtual/range {v3 .. v8}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-eqz p0, :cond_5

    .line 107
    .line 108
    :goto_5
    invoke-virtual {v4}, Lxy0/j;->B()Z

    .line 109
    .line 110
    .line 111
    if-eqz v10, :cond_c

    .line 112
    .line 113
    :goto_6
    sget-object p0, Lxy0/j;->m:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 114
    .line 115
    invoke-virtual {p0, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    if-nez p1, :cond_8

    .line 120
    .line 121
    sget-object p2, Lxy0/l;->q:Lj51/i;

    .line 122
    .line 123
    goto :goto_7

    .line 124
    :cond_8
    sget-object p2, Lxy0/l;->r:Lj51/i;

    .line 125
    .line 126
    :cond_9
    :goto_7
    invoke-virtual {p0, v4, p1, p2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_b

    .line 131
    .line 132
    if-nez p1, :cond_a

    .line 133
    .line 134
    goto :goto_8

    .line 135
    :cond_a
    invoke-static {v9, p1}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    check-cast p1, Lay0/k;

    .line 139
    .line 140
    invoke-virtual {v4}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    return v10

    .line 148
    :cond_b
    invoke-virtual {p0, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    if-eq v0, p1, :cond_9

    .line 153
    .line 154
    goto :goto_6

    .line 155
    :cond_c
    :goto_8
    return v10
.end method

.method public final k(J)Lxy0/r;
    .locals 12

    .line 1
    sget-object v0, Lxy0/j;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lxy0/j;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lxy0/r;

    .line 14
    .line 15
    iget-wide v2, v1, Laz0/q;->f:J

    .line 16
    .line 17
    move-object v4, v0

    .line 18
    check-cast v4, Lxy0/r;

    .line 19
    .line 20
    iget-wide v4, v4, Laz0/q;->f:J

    .line 21
    .line 22
    cmp-long v2, v2, v4

    .line 23
    .line 24
    if-lez v2, :cond_0

    .line 25
    .line 26
    move-object v0, v1

    .line 27
    :cond_0
    sget-object v1, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 28
    .line 29
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Lxy0/r;

    .line 34
    .line 35
    iget-wide v2, v1, Laz0/q;->f:J

    .line 36
    .line 37
    move-object v4, v0

    .line 38
    check-cast v4, Lxy0/r;

    .line 39
    .line 40
    iget-wide v4, v4, Laz0/q;->f:J

    .line 41
    .line 42
    cmp-long v2, v2, v4

    .line 43
    .line 44
    if-lez v2, :cond_1

    .line 45
    .line 46
    move-object v0, v1

    .line 47
    :cond_1
    check-cast v0, Laz0/c;

    .line 48
    .line 49
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    sget-object v1, Laz0/c;->d:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 53
    .line 54
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    sget-object v3, Laz0/b;->a:Lj51/i;

    .line 59
    .line 60
    const/4 v4, 0x0

    .line 61
    if-ne v2, v3, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    check-cast v2, Laz0/c;

    .line 65
    .line 66
    if-nez v2, :cond_15

    .line 67
    .line 68
    :cond_3
    invoke-virtual {v1, v0, v4, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_14

    .line 73
    .line 74
    :goto_1
    check-cast v0, Lxy0/r;

    .line 75
    .line 76
    invoke-virtual {p0}, Lxy0/j;->C()Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    const/4 v2, 0x1

    .line 81
    const/4 v3, -0x1

    .line 82
    if-eqz v1, :cond_a

    .line 83
    .line 84
    move-object v1, v0

    .line 85
    :cond_4
    sget v5, Lxy0/l;->b:I

    .line 86
    .line 87
    sub-int/2addr v5, v2

    .line 88
    :goto_2
    const-wide/16 v6, -0x1

    .line 89
    .line 90
    if-ge v3, v5, :cond_9

    .line 91
    .line 92
    iget-wide v8, v1, Laz0/q;->f:J

    .line 93
    .line 94
    sget v10, Lxy0/l;->b:I

    .line 95
    .line 96
    int-to-long v10, v10

    .line 97
    mul-long/2addr v8, v10

    .line 98
    int-to-long v10, v5

    .line 99
    add-long/2addr v8, v10

    .line 100
    sget-object v10, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 101
    .line 102
    invoke-virtual {v10, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 103
    .line 104
    .line 105
    move-result-wide v10

    .line 106
    cmp-long v10, v8, v10

    .line 107
    .line 108
    if-gez v10, :cond_5

    .line 109
    .line 110
    :goto_3
    move-wide v8, v6

    .line 111
    goto :goto_5

    .line 112
    :cond_5
    invoke-virtual {v1, v5}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v10

    .line 116
    if-eqz v10, :cond_7

    .line 117
    .line 118
    sget-object v11, Lxy0/l;->e:Lj51/i;

    .line 119
    .line 120
    if-ne v10, v11, :cond_6

    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_6
    sget-object v11, Lxy0/l;->d:Lj51/i;

    .line 124
    .line 125
    if-ne v10, v11, :cond_8

    .line 126
    .line 127
    goto :goto_5

    .line 128
    :cond_7
    :goto_4
    sget-object v11, Lxy0/l;->l:Lj51/i;

    .line 129
    .line 130
    invoke-virtual {v1, v5, v10, v11}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v10

    .line 134
    if-eqz v10, :cond_5

    .line 135
    .line 136
    invoke-virtual {v1}, Laz0/q;->i()V

    .line 137
    .line 138
    .line 139
    :cond_8
    add-int/lit8 v5, v5, -0x1

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_9
    sget-object v5, Laz0/c;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 143
    .line 144
    invoke-virtual {v5, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    check-cast v1, Laz0/c;

    .line 149
    .line 150
    check-cast v1, Lxy0/r;

    .line 151
    .line 152
    if-nez v1, :cond_4

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :goto_5
    cmp-long v1, v8, v6

    .line 156
    .line 157
    if-eqz v1, :cond_a

    .line 158
    .line 159
    invoke-virtual {p0, v8, v9}, Lxy0/j;->l(J)V

    .line 160
    .line 161
    .line 162
    :cond_a
    move-object v1, v0

    .line 163
    :goto_6
    if-eqz v1, :cond_11

    .line 164
    .line 165
    sget v5, Lxy0/l;->b:I

    .line 166
    .line 167
    sub-int/2addr v5, v2

    .line 168
    :goto_7
    if-ge v3, v5, :cond_10

    .line 169
    .line 170
    iget-wide v6, v1, Laz0/q;->f:J

    .line 171
    .line 172
    sget v8, Lxy0/l;->b:I

    .line 173
    .line 174
    int-to-long v8, v8

    .line 175
    mul-long/2addr v6, v8

    .line 176
    int-to-long v8, v5

    .line 177
    add-long/2addr v6, v8

    .line 178
    cmp-long v6, v6, p1

    .line 179
    .line 180
    if-ltz v6, :cond_11

    .line 181
    .line 182
    :cond_b
    invoke-virtual {v1, v5}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    if-eqz v6, :cond_e

    .line 187
    .line 188
    sget-object v7, Lxy0/l;->e:Lj51/i;

    .line 189
    .line 190
    if-ne v6, v7, :cond_c

    .line 191
    .line 192
    goto :goto_8

    .line 193
    :cond_c
    instance-of v7, v6, Lxy0/b0;

    .line 194
    .line 195
    if-eqz v7, :cond_d

    .line 196
    .line 197
    sget-object v7, Lxy0/l;->l:Lj51/i;

    .line 198
    .line 199
    invoke-virtual {v1, v5, v6, v7}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v7

    .line 203
    if-eqz v7, :cond_b

    .line 204
    .line 205
    check-cast v6, Lxy0/b0;

    .line 206
    .line 207
    iget-object v6, v6, Lxy0/b0;->a:Lvy0/k2;

    .line 208
    .line 209
    invoke-static {v4, v6}, Laz0/b;->f(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v4

    .line 213
    invoke-virtual {v1, v5, v2}, Lxy0/r;->m(IZ)V

    .line 214
    .line 215
    .line 216
    goto :goto_9

    .line 217
    :cond_d
    instance-of v7, v6, Lvy0/k2;

    .line 218
    .line 219
    if-eqz v7, :cond_f

    .line 220
    .line 221
    sget-object v7, Lxy0/l;->l:Lj51/i;

    .line 222
    .line 223
    invoke-virtual {v1, v5, v6, v7}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v7

    .line 227
    if-eqz v7, :cond_b

    .line 228
    .line 229
    invoke-static {v4, v6}, Laz0/b;->f(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v4

    .line 233
    invoke-virtual {v1, v5, v2}, Lxy0/r;->m(IZ)V

    .line 234
    .line 235
    .line 236
    goto :goto_9

    .line 237
    :cond_e
    :goto_8
    sget-object v7, Lxy0/l;->l:Lj51/i;

    .line 238
    .line 239
    invoke-virtual {v1, v5, v6, v7}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v6

    .line 243
    if-eqz v6, :cond_b

    .line 244
    .line 245
    invoke-virtual {v1}, Laz0/q;->i()V

    .line 246
    .line 247
    .line 248
    :cond_f
    :goto_9
    add-int/lit8 v5, v5, -0x1

    .line 249
    .line 250
    goto :goto_7

    .line 251
    :cond_10
    sget-object v5, Laz0/c;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 252
    .line 253
    invoke-virtual {v5, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    check-cast v1, Laz0/c;

    .line 258
    .line 259
    check-cast v1, Lxy0/r;

    .line 260
    .line 261
    goto :goto_6

    .line 262
    :cond_11
    if-eqz v4, :cond_13

    .line 263
    .line 264
    instance-of p1, v4, Ljava/util/ArrayList;

    .line 265
    .line 266
    if-nez p1, :cond_12

    .line 267
    .line 268
    check-cast v4, Lvy0/k2;

    .line 269
    .line 270
    invoke-virtual {p0, v4, v2}, Lxy0/j;->I(Lvy0/k2;Z)V

    .line 271
    .line 272
    .line 273
    return-object v0

    .line 274
    :cond_12
    check-cast v4, Ljava/util/ArrayList;

    .line 275
    .line 276
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 277
    .line 278
    .line 279
    move-result p1

    .line 280
    sub-int/2addr p1, v2

    .line 281
    :goto_a
    if-ge v3, p1, :cond_13

    .line 282
    .line 283
    invoke-virtual {v4, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object p2

    .line 287
    check-cast p2, Lvy0/k2;

    .line 288
    .line 289
    invoke-virtual {p0, p2, v2}, Lxy0/j;->I(Lvy0/k2;Z)V

    .line 290
    .line 291
    .line 292
    add-int/lit8 p1, p1, -0x1

    .line 293
    .line 294
    goto :goto_a

    .line 295
    :cond_13
    return-object v0

    .line 296
    :cond_14
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v2

    .line 300
    if-eqz v2, :cond_3

    .line 301
    .line 302
    goto/16 :goto_0

    .line 303
    .line 304
    :cond_15
    move-object v0, v2

    .line 305
    goto/16 :goto_0
.end method

.method public final l(J)V
    .locals 9

    .line 1
    sget-object v0, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lxy0/r;

    .line 8
    .line 9
    :goto_0
    sget-object v1, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 10
    .line 11
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 12
    .line 13
    .line 14
    move-result-wide v3

    .line 15
    iget v2, p0, Lxy0/j;->d:I

    .line 16
    .line 17
    int-to-long v5, v2

    .line 18
    add-long/2addr v5, v3

    .line 19
    sget-object v2, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 20
    .line 21
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v7

    .line 25
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->max(JJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide v5

    .line 29
    cmp-long v2, p1, v5

    .line 30
    .line 31
    if-gez v2, :cond_0

    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    const-wide/16 v5, 0x1

    .line 35
    .line 36
    add-long/2addr v5, v3

    .line 37
    move-object v2, p0

    .line 38
    invoke-virtual/range {v1 .. v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_5

    .line 43
    .line 44
    sget p0, Lxy0/l;->b:I

    .line 45
    .line 46
    int-to-long v5, p0

    .line 47
    div-long v7, v3, v5

    .line 48
    .line 49
    rem-long v5, v3, v5

    .line 50
    .line 51
    long-to-int p0, v5

    .line 52
    iget-wide v5, v0, Laz0/q;->f:J

    .line 53
    .line 54
    cmp-long v1, v5, v7

    .line 55
    .line 56
    if-eqz v1, :cond_2

    .line 57
    .line 58
    invoke-virtual {v2, v7, v8, v0}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    if-nez v1, :cond_1

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_1
    move-object v0, v1

    .line 66
    :cond_2
    const/4 v7, 0x0

    .line 67
    move-wide v5, v3

    .line 68
    move v4, p0

    .line 69
    move-object v3, v0

    .line 70
    invoke-virtual/range {v2 .. v7}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    sget-object v0, Lxy0/l;->o:Lj51/i;

    .line 75
    .line 76
    if-ne p0, v0, :cond_3

    .line 77
    .line 78
    invoke-virtual {v2}, Lxy0/j;->w()J

    .line 79
    .line 80
    .line 81
    move-result-wide v0

    .line 82
    cmp-long p0, v5, v0

    .line 83
    .line 84
    if-gez p0, :cond_4

    .line 85
    .line 86
    invoke-virtual {v3}, Laz0/c;->b()V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_3
    invoke-virtual {v3}, Laz0/c;->b()V

    .line 91
    .line 92
    .line 93
    :cond_4
    :goto_1
    move-object p0, v2

    .line 94
    move-object v0, v3

    .line 95
    goto :goto_0

    .line 96
    :cond_5
    :goto_2
    move-object p0, v2

    .line 97
    goto :goto_0
.end method

.method public final m()Lcom/google/firebase/messaging/w;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    sget-object v2, Lxy0/f;->d:Lxy0/f;

    .line 4
    .line 5
    const/4 v1, 0x3

    .line 6
    invoke-static {v1, v2}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    sget-object v3, Lxy0/g;->d:Lxy0/g;

    .line 10
    .line 11
    invoke-static {v1, v3}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/16 v5, 0x9

    .line 16
    .line 17
    move-object v1, p0

    .line 18
    invoke-direct/range {v0 .. v5}, Lcom/google/firebase/messaging/w;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method

.method public final n()Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v0, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    sget-object v3, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 8
    .line 9
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 10
    .line 11
    .line 12
    move-result-wide v3

    .line 13
    const/4 v5, 0x1

    .line 14
    invoke-virtual {p0, v3, v4, v5}, Lxy0/j;->z(JZ)Z

    .line 15
    .line 16
    .line 17
    move-result v5

    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    new-instance v0, Lxy0/o;

    .line 25
    .line 26
    invoke-direct {v0, p0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    :cond_0
    const-wide v5, 0xfffffffffffffffL

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    and-long/2addr v3, v5

    .line 36
    cmp-long v1, v1, v3

    .line 37
    .line 38
    sget-object v2, Lxy0/q;->b:Lxy0/p;

    .line 39
    .line 40
    if-ltz v1, :cond_1

    .line 41
    .line 42
    return-object v2

    .line 43
    :cond_1
    sget-object v8, Lxy0/l;->k:Lj51/i;

    .line 44
    .line 45
    sget-object v1, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 46
    .line 47
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Lxy0/r;

    .line 52
    .line 53
    :goto_0
    invoke-virtual {p0}, Lxy0/j;->A()Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-eqz v3, :cond_2

    .line 58
    .line 59
    invoke-virtual {p0}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    new-instance v0, Lxy0/o;

    .line 64
    .line 65
    invoke-direct {v0, p0}, Lxy0/o;-><init>(Ljava/lang/Throwable;)V

    .line 66
    .line 67
    .line 68
    return-object v0

    .line 69
    :cond_2
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 70
    .line 71
    .line 72
    move-result-wide v6

    .line 73
    sget v3, Lxy0/l;->b:I

    .line 74
    .line 75
    int-to-long v3, v3

    .line 76
    div-long v9, v6, v3

    .line 77
    .line 78
    rem-long v3, v6, v3

    .line 79
    .line 80
    long-to-int v5, v3

    .line 81
    iget-wide v3, v1, Laz0/q;->f:J

    .line 82
    .line 83
    cmp-long v3, v3, v9

    .line 84
    .line 85
    if-eqz v3, :cond_4

    .line 86
    .line 87
    invoke-virtual {p0, v9, v10, v1}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    if-nez v3, :cond_3

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_3
    move-object v4, v3

    .line 95
    :goto_1
    move-object v3, p0

    .line 96
    goto :goto_2

    .line 97
    :cond_4
    move-object v4, v1

    .line 98
    goto :goto_1

    .line 99
    :goto_2
    invoke-virtual/range {v3 .. v8}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    move-object v1, v4

    .line 104
    sget-object v4, Lxy0/l;->m:Lj51/i;

    .line 105
    .line 106
    if-ne p0, v4, :cond_7

    .line 107
    .line 108
    instance-of p0, v8, Lvy0/k2;

    .line 109
    .line 110
    if-eqz p0, :cond_5

    .line 111
    .line 112
    check-cast v8, Lvy0/k2;

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_5
    const/4 v8, 0x0

    .line 116
    :goto_3
    if-eqz v8, :cond_6

    .line 117
    .line 118
    invoke-interface {v8, v1, v5}, Lvy0/k2;->b(Laz0/q;I)V

    .line 119
    .line 120
    .line 121
    :cond_6
    invoke-virtual {v3, v6, v7}, Lxy0/j;->N(J)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v1}, Laz0/q;->i()V

    .line 125
    .line 126
    .line 127
    return-object v2

    .line 128
    :cond_7
    sget-object v4, Lxy0/l;->o:Lj51/i;

    .line 129
    .line 130
    if-ne p0, v4, :cond_9

    .line 131
    .line 132
    invoke-virtual {v3}, Lxy0/j;->w()J

    .line 133
    .line 134
    .line 135
    move-result-wide v4

    .line 136
    cmp-long p0, v6, v4

    .line 137
    .line 138
    if-gez p0, :cond_8

    .line 139
    .line 140
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 141
    .line 142
    .line 143
    :cond_8
    move-object p0, v3

    .line 144
    goto :goto_0

    .line 145
    :cond_9
    sget-object v0, Lxy0/l;->n:Lj51/i;

    .line 146
    .line 147
    if-eq p0, v0, :cond_a

    .line 148
    .line 149
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 150
    .line 151
    .line 152
    return-object p0

    .line 153
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 154
    .line 155
    const-string v0, "unexpected"

    .line 156
    .line 157
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw p0
.end method

.method public final o(Lci0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lxy0/j;->G(Lxy0/j;Lrx0/c;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final p()V
    .locals 15

    .line 1
    invoke-virtual {p0}, Lxy0/j;->D()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    sget-object v6, Lxy0/j;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 9
    .line 10
    invoke-virtual {v6, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lxy0/r;

    .line 15
    .line 16
    move-object v7, v0

    .line 17
    :goto_0
    sget-object v0, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 20
    .line 21
    .line 22
    move-result-wide v8

    .line 23
    sget v0, Lxy0/l;->b:I

    .line 24
    .line 25
    int-to-long v2, v0

    .line 26
    div-long v2, v8, v2

    .line 27
    .line 28
    invoke-virtual {p0}, Lxy0/j;->w()J

    .line 29
    .line 30
    .line 31
    move-result-wide v4

    .line 32
    cmp-long v0, v4, v8

    .line 33
    .line 34
    if-gtz v0, :cond_2

    .line 35
    .line 36
    iget-wide v4, v7, Laz0/q;->f:J

    .line 37
    .line 38
    cmp-long v0, v4, v2

    .line 39
    .line 40
    if-gez v0, :cond_1

    .line 41
    .line 42
    invoke-virtual {v7}, Laz0/c;->c()Laz0/c;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    if-eqz v0, :cond_1

    .line 47
    .line 48
    invoke-virtual {p0, v2, v3, v7}, Lxy0/j;->E(JLxy0/r;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    invoke-static {p0}, Lxy0/j;->y(Lxy0/j;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_2
    iget-wide v4, v7, Laz0/q;->f:J

    .line 56
    .line 57
    cmp-long v0, v4, v2

    .line 58
    .line 59
    if-eqz v0, :cond_d

    .line 60
    .line 61
    sget-object v0, Lxy0/k;->d:Lxy0/k;

    .line 62
    .line 63
    :goto_1
    invoke-static {v7, v2, v3, v0}, Laz0/b;->b(Laz0/q;JLay0/n;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    invoke-static {v4}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    if-nez v5, :cond_7

    .line 72
    .line 73
    invoke-static {v4}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    :cond_3
    :goto_2
    invoke-virtual {v6, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v10

    .line 81
    check-cast v10, Laz0/q;

    .line 82
    .line 83
    iget-wide v11, v10, Laz0/q;->f:J

    .line 84
    .line 85
    iget-wide v13, v5, Laz0/q;->f:J

    .line 86
    .line 87
    cmp-long v11, v11, v13

    .line 88
    .line 89
    if-ltz v11, :cond_4

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    invoke-virtual {v5}, Laz0/q;->j()Z

    .line 93
    .line 94
    .line 95
    move-result v11

    .line 96
    if-nez v11, :cond_5

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_5
    invoke-virtual {v6, p0, v10, v5}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v11

    .line 103
    if-eqz v11, :cond_6

    .line 104
    .line 105
    invoke-virtual {v10}, Laz0/q;->f()Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-eqz v0, :cond_7

    .line 110
    .line 111
    invoke-virtual {v10}, Laz0/c;->e()V

    .line 112
    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_6
    invoke-virtual {v6, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v11

    .line 119
    if-eq v11, v10, :cond_5

    .line 120
    .line 121
    invoke-virtual {v5}, Laz0/q;->f()Z

    .line 122
    .line 123
    .line 124
    move-result v10

    .line 125
    if-eqz v10, :cond_3

    .line 126
    .line 127
    invoke-virtual {v5}, Laz0/c;->e()V

    .line 128
    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_7
    :goto_3
    invoke-static {v4}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    const/4 v10, 0x0

    .line 136
    if-eqz v0, :cond_8

    .line 137
    .line 138
    invoke-virtual {p0}, Lxy0/j;->B()Z

    .line 139
    .line 140
    .line 141
    invoke-virtual {p0, v2, v3, v7}, Lxy0/j;->E(JLxy0/r;)V

    .line 142
    .line 143
    .line 144
    invoke-static {p0}, Lxy0/j;->y(Lxy0/j;)V

    .line 145
    .line 146
    .line 147
    goto :goto_5

    .line 148
    :cond_8
    invoke-static {v4}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    check-cast v0, Lxy0/r;

    .line 153
    .line 154
    iget-wide v4, v0, Laz0/q;->f:J

    .line 155
    .line 156
    cmp-long v2, v4, v2

    .line 157
    .line 158
    if-lez v2, :cond_a

    .line 159
    .line 160
    const-wide/16 v2, 0x1

    .line 161
    .line 162
    add-long/2addr v2, v8

    .line 163
    sget v0, Lxy0/l;->b:I

    .line 164
    .line 165
    int-to-long v11, v0

    .line 166
    mul-long/2addr v4, v11

    .line 167
    sget-object v0, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 168
    .line 169
    move-object v1, p0

    .line 170
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-eqz v0, :cond_9

    .line 175
    .line 176
    sub-long/2addr v4, v8

    .line 177
    sget-object v0, Lxy0/j;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 178
    .line 179
    invoke-virtual {v0, p0, v4, v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->addAndGet(Ljava/lang/Object;J)J

    .line 180
    .line 181
    .line 182
    move-result-wide v2

    .line 183
    const-wide/high16 v4, 0x4000000000000000L    # 2.0

    .line 184
    .line 185
    and-long/2addr v2, v4

    .line 186
    const-wide/16 v11, 0x0

    .line 187
    .line 188
    cmp-long v2, v2, v11

    .line 189
    .line 190
    if-eqz v2, :cond_b

    .line 191
    .line 192
    :goto_4
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 193
    .line 194
    .line 195
    move-result-wide v2

    .line 196
    and-long/2addr v2, v4

    .line 197
    cmp-long v2, v2, v11

    .line 198
    .line 199
    if-eqz v2, :cond_b

    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_9
    invoke-static {p0}, Lxy0/j;->y(Lxy0/j;)V

    .line 203
    .line 204
    .line 205
    goto :goto_5

    .line 206
    :cond_a
    move-object v10, v0

    .line 207
    :cond_b
    :goto_5
    if-nez v10, :cond_c

    .line 208
    .line 209
    goto/16 :goto_0

    .line 210
    .line 211
    :cond_c
    move-object v7, v10

    .line 212
    :cond_d
    sget v0, Lxy0/l;->b:I

    .line 213
    .line 214
    int-to-long v2, v0

    .line 215
    rem-long v2, v8, v2

    .line 216
    .line 217
    long-to-int v0, v2

    .line 218
    invoke-virtual {v7, v0}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v2

    .line 222
    instance-of v3, v2, Lvy0/k2;

    .line 223
    .line 224
    sget-object v4, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 225
    .line 226
    if-eqz v3, :cond_f

    .line 227
    .line 228
    invoke-virtual {v4, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 229
    .line 230
    .line 231
    move-result-wide v10

    .line 232
    cmp-long v3, v8, v10

    .line 233
    .line 234
    if-ltz v3, :cond_f

    .line 235
    .line 236
    sget-object v3, Lxy0/l;->g:Lj51/i;

    .line 237
    .line 238
    invoke-virtual {v7, v0, v2, v3}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    move-result v3

    .line 242
    if-eqz v3, :cond_f

    .line 243
    .line 244
    invoke-virtual {p0, v2, v7, v0}, Lxy0/j;->K(Ljava/lang/Object;Lxy0/r;I)Z

    .line 245
    .line 246
    .line 247
    move-result v2

    .line 248
    if-eqz v2, :cond_e

    .line 249
    .line 250
    sget-object v2, Lxy0/l;->d:Lj51/i;

    .line 251
    .line 252
    invoke-virtual {v7, v0, v2}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    goto/16 :goto_8

    .line 256
    .line 257
    :cond_e
    sget-object v2, Lxy0/l;->j:Lj51/i;

    .line 258
    .line 259
    invoke-virtual {v7, v0, v2}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v7}, Laz0/q;->i()V

    .line 263
    .line 264
    .line 265
    goto :goto_7

    .line 266
    :cond_f
    :goto_6
    invoke-virtual {v7, v0}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v2

    .line 270
    instance-of v3, v2, Lvy0/k2;

    .line 271
    .line 272
    if-eqz v3, :cond_12

    .line 273
    .line 274
    invoke-virtual {v4, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 275
    .line 276
    .line 277
    move-result-wide v10

    .line 278
    cmp-long v3, v8, v10

    .line 279
    .line 280
    if-gez v3, :cond_10

    .line 281
    .line 282
    new-instance v3, Lxy0/b0;

    .line 283
    .line 284
    move-object v5, v2

    .line 285
    check-cast v5, Lvy0/k2;

    .line 286
    .line 287
    invoke-direct {v3, v5}, Lxy0/b0;-><init>(Lvy0/k2;)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v7, v0, v2, v3}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 291
    .line 292
    .line 293
    move-result v2

    .line 294
    if-eqz v2, :cond_f

    .line 295
    .line 296
    goto/16 :goto_8

    .line 297
    .line 298
    :cond_10
    sget-object v3, Lxy0/l;->g:Lj51/i;

    .line 299
    .line 300
    invoke-virtual {v7, v0, v2, v3}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v3

    .line 304
    if-eqz v3, :cond_f

    .line 305
    .line 306
    invoke-virtual {p0, v2, v7, v0}, Lxy0/j;->K(Ljava/lang/Object;Lxy0/r;I)Z

    .line 307
    .line 308
    .line 309
    move-result v2

    .line 310
    if-eqz v2, :cond_11

    .line 311
    .line 312
    sget-object v2, Lxy0/l;->d:Lj51/i;

    .line 313
    .line 314
    invoke-virtual {v7, v0, v2}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 315
    .line 316
    .line 317
    goto :goto_8

    .line 318
    :cond_11
    sget-object v2, Lxy0/l;->j:Lj51/i;

    .line 319
    .line 320
    invoke-virtual {v7, v0, v2}, Lxy0/r;->o(ILjava/lang/Object;)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {v7}, Laz0/q;->i()V

    .line 324
    .line 325
    .line 326
    goto :goto_7

    .line 327
    :cond_12
    sget-object v3, Lxy0/l;->j:Lj51/i;

    .line 328
    .line 329
    if-ne v2, v3, :cond_13

    .line 330
    .line 331
    :goto_7
    invoke-static {p0}, Lxy0/j;->y(Lxy0/j;)V

    .line 332
    .line 333
    .line 334
    goto/16 :goto_0

    .line 335
    .line 336
    :cond_13
    if-nez v2, :cond_14

    .line 337
    .line 338
    sget-object v3, Lxy0/l;->e:Lj51/i;

    .line 339
    .line 340
    invoke-virtual {v7, v0, v2, v3}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v2

    .line 344
    if-eqz v2, :cond_f

    .line 345
    .line 346
    goto :goto_8

    .line 347
    :cond_14
    sget-object v3, Lxy0/l;->d:Lj51/i;

    .line 348
    .line 349
    if-ne v2, v3, :cond_15

    .line 350
    .line 351
    goto :goto_8

    .line 352
    :cond_15
    sget-object v3, Lxy0/l;->h:Lj51/i;

    .line 353
    .line 354
    if-eq v2, v3, :cond_19

    .line 355
    .line 356
    sget-object v3, Lxy0/l;->i:Lj51/i;

    .line 357
    .line 358
    if-eq v2, v3, :cond_19

    .line 359
    .line 360
    sget-object v3, Lxy0/l;->k:Lj51/i;

    .line 361
    .line 362
    if-ne v2, v3, :cond_16

    .line 363
    .line 364
    goto :goto_8

    .line 365
    :cond_16
    sget-object v3, Lxy0/l;->l:Lj51/i;

    .line 366
    .line 367
    if-ne v2, v3, :cond_17

    .line 368
    .line 369
    goto :goto_8

    .line 370
    :cond_17
    sget-object v3, Lxy0/l;->f:Lj51/i;

    .line 371
    .line 372
    if-ne v2, v3, :cond_18

    .line 373
    .line 374
    goto :goto_6

    .line 375
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 376
    .line 377
    new-instance v1, Ljava/lang/StringBuilder;

    .line 378
    .line 379
    const-string v3, "Unexpected cell state: "

    .line 380
    .line 381
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 388
    .line 389
    .line 390
    move-result-object v1

    .line 391
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 392
    .line 393
    .line 394
    move-result-object v1

    .line 395
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    throw v0

    .line 399
    :cond_19
    :goto_8
    invoke-static {p0}, Lxy0/j;->y(Lxy0/j;)V

    .line 400
    .line 401
    .line 402
    return-void
.end method

.method public final q(JLxy0/r;)Lxy0/r;
    .locals 9

    .line 1
    sget-object v0, Lxy0/l;->a:Lxy0/r;

    .line 2
    .line 3
    sget-object v0, Lxy0/k;->d:Lxy0/k;

    .line 4
    .line 5
    :goto_0
    invoke-static {p3, p1, p2, v0}, Laz0/b;->b(Laz0/q;JLay0/n;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v1}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-nez v2, :cond_4

    .line 14
    .line 15
    invoke-static {v1}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    :cond_0
    :goto_1
    sget-object v3, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 20
    .line 21
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    check-cast v4, Laz0/q;

    .line 26
    .line 27
    iget-wide v5, v4, Laz0/q;->f:J

    .line 28
    .line 29
    iget-wide v7, v2, Laz0/q;->f:J

    .line 30
    .line 31
    cmp-long v5, v5, v7

    .line 32
    .line 33
    if-ltz v5, :cond_1

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_1
    invoke-virtual {v2}, Laz0/q;->j()Z

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    if-nez v5, :cond_2

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-virtual {v3, p0, v4, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    if-eqz v5, :cond_3

    .line 48
    .line 49
    invoke-virtual {v4}, Laz0/q;->f()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_4

    .line 54
    .line 55
    invoke-virtual {v4}, Laz0/c;->e()V

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    if-eq v5, v4, :cond_2

    .line 64
    .line 65
    invoke-virtual {v2}, Laz0/q;->f()Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-eqz v3, :cond_0

    .line 70
    .line 71
    invoke-virtual {v2}, Laz0/c;->e()V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_4
    :goto_2
    invoke-static {v1}, Laz0/b;->e(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    const/4 v2, 0x0

    .line 80
    if-eqz v0, :cond_5

    .line 81
    .line 82
    invoke-virtual {p0}, Lxy0/j;->B()Z

    .line 83
    .line 84
    .line 85
    iget-wide p1, p3, Laz0/q;->f:J

    .line 86
    .line 87
    sget v0, Lxy0/l;->b:I

    .line 88
    .line 89
    int-to-long v0, v0

    .line 90
    mul-long/2addr p1, v0

    .line 91
    invoke-virtual {p0}, Lxy0/j;->w()J

    .line 92
    .line 93
    .line 94
    move-result-wide v0

    .line 95
    cmp-long p0, p1, v0

    .line 96
    .line 97
    if-gez p0, :cond_b

    .line 98
    .line 99
    invoke-virtual {p3}, Laz0/c;->b()V

    .line 100
    .line 101
    .line 102
    return-object v2

    .line 103
    :cond_5
    invoke-static {v1}, Laz0/b;->c(Ljava/lang/Object;)Laz0/q;

    .line 104
    .line 105
    .line 106
    move-result-object p3

    .line 107
    check-cast p3, Lxy0/r;

    .line 108
    .line 109
    iget-wide v0, p3, Laz0/q;->f:J

    .line 110
    .line 111
    invoke-virtual {p0}, Lxy0/j;->D()Z

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    if-nez v3, :cond_9

    .line 116
    .line 117
    sget-object v3, Lxy0/j;->g:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 118
    .line 119
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 120
    .line 121
    .line 122
    move-result-wide v3

    .line 123
    sget v5, Lxy0/l;->b:I

    .line 124
    .line 125
    int-to-long v5, v5

    .line 126
    div-long/2addr v3, v5

    .line 127
    cmp-long v3, p1, v3

    .line 128
    .line 129
    if-gtz v3, :cond_9

    .line 130
    .line 131
    :cond_6
    :goto_3
    sget-object v3, Lxy0/j;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 132
    .line 133
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    check-cast v4, Laz0/q;

    .line 138
    .line 139
    iget-wide v5, v4, Laz0/q;->f:J

    .line 140
    .line 141
    cmp-long v5, v5, v0

    .line 142
    .line 143
    if-gez v5, :cond_9

    .line 144
    .line 145
    invoke-virtual {p3}, Laz0/q;->j()Z

    .line 146
    .line 147
    .line 148
    move-result v5

    .line 149
    if-eqz v5, :cond_9

    .line 150
    .line 151
    :cond_7
    invoke-virtual {v3, p0, v4, p3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v5

    .line 155
    if-eqz v5, :cond_8

    .line 156
    .line 157
    invoke-virtual {v4}, Laz0/q;->f()Z

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    if-eqz v3, :cond_9

    .line 162
    .line 163
    invoke-virtual {v4}, Laz0/c;->e()V

    .line 164
    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_8
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    if-eq v5, v4, :cond_7

    .line 172
    .line 173
    invoke-virtual {p3}, Laz0/q;->f()Z

    .line 174
    .line 175
    .line 176
    move-result v3

    .line 177
    if-eqz v3, :cond_6

    .line 178
    .line 179
    invoke-virtual {p3}, Laz0/c;->e()V

    .line 180
    .line 181
    .line 182
    goto :goto_3

    .line 183
    :cond_9
    :goto_4
    cmp-long p1, v0, p1

    .line 184
    .line 185
    if-lez p1, :cond_d

    .line 186
    .line 187
    sget p1, Lxy0/l;->b:I

    .line 188
    .line 189
    int-to-long p1, p1

    .line 190
    mul-long v7, v0, p1

    .line 191
    .line 192
    :goto_5
    sget-object p1, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 193
    .line 194
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 195
    .line 196
    .line 197
    move-result-wide v5

    .line 198
    cmp-long p1, v5, v7

    .line 199
    .line 200
    if-ltz p1, :cond_a

    .line 201
    .line 202
    move-object v4, p0

    .line 203
    goto :goto_6

    .line 204
    :cond_a
    sget-object v3, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 205
    .line 206
    move-object v4, p0

    .line 207
    invoke-virtual/range {v3 .. v8}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 208
    .line 209
    .line 210
    move-result p0

    .line 211
    if-eqz p0, :cond_c

    .line 212
    .line 213
    :goto_6
    sget p0, Lxy0/l;->b:I

    .line 214
    .line 215
    int-to-long p0, p0

    .line 216
    mul-long/2addr v0, p0

    .line 217
    invoke-virtual {v4}, Lxy0/j;->w()J

    .line 218
    .line 219
    .line 220
    move-result-wide p0

    .line 221
    cmp-long p0, v0, p0

    .line 222
    .line 223
    if-gez p0, :cond_b

    .line 224
    .line 225
    invoke-virtual {p3}, Laz0/c;->b()V

    .line 226
    .line 227
    .line 228
    :cond_b
    return-object v2

    .line 229
    :cond_c
    move-object p0, v4

    .line 230
    goto :goto_5

    .line 231
    :cond_d
    return-object p3
.end method

.method public final r(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lxy0/r;

    .line 8
    .line 9
    :goto_0
    invoke-virtual {p0}, Lxy0/j;->A()Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-nez v2, :cond_10

    .line 14
    .line 15
    sget-object v2, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 16
    .line 17
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v6

    .line 21
    sget v3, Lxy0/l;->b:I

    .line 22
    .line 23
    int-to-long v3, v3

    .line 24
    div-long v8, v6, v3

    .line 25
    .line 26
    rem-long v3, v6, v3

    .line 27
    .line 28
    long-to-int v5, v3

    .line 29
    iget-wide v3, v1, Laz0/q;->f:J

    .line 30
    .line 31
    cmp-long v3, v3, v8

    .line 32
    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    invoke-virtual {p0, v8, v9, v1}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    if-nez v3, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    move-object v4, v3

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move-object v4, v1

    .line 45
    :goto_1
    const/4 v8, 0x0

    .line 46
    move-object v3, p0

    .line 47
    invoke-virtual/range {v3 .. v8}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    sget-object v1, Lxy0/l;->m:Lj51/i;

    .line 52
    .line 53
    const-string v11, "unexpected"

    .line 54
    .line 55
    if-eq p0, v1, :cond_f

    .line 56
    .line 57
    sget-object v9, Lxy0/l;->o:Lj51/i;

    .line 58
    .line 59
    if-ne p0, v9, :cond_3

    .line 60
    .line 61
    invoke-virtual {v3}, Lxy0/j;->w()J

    .line 62
    .line 63
    .line 64
    move-result-wide v1

    .line 65
    cmp-long p0, v6, v1

    .line 66
    .line 67
    if-gez p0, :cond_2

    .line 68
    .line 69
    invoke-virtual {v4}, Laz0/c;->b()V

    .line 70
    .line 71
    .line 72
    :cond_2
    move-object p0, v3

    .line 73
    move-object v1, v4

    .line 74
    goto :goto_0

    .line 75
    :cond_3
    sget-object v8, Lxy0/l;->n:Lj51/i;

    .line 76
    .line 77
    if-ne p0, v8, :cond_e

    .line 78
    .line 79
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-static {p0}, Lvy0/e0;->x(Lkotlin/coroutines/Continuation;)Lvy0/l;

    .line 84
    .line 85
    .line 86
    move-result-object v8

    .line 87
    :try_start_0
    invoke-virtual/range {v3 .. v8}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-ne p0, v1, :cond_4

    .line 92
    .line 93
    invoke-virtual {v8, v4, v5}, Lvy0/l;->b(Laz0/q;I)V

    .line 94
    .line 95
    .line 96
    goto/16 :goto_7

    .line 97
    .line 98
    :catchall_0
    move-exception v0

    .line 99
    :goto_2
    move-object p0, v0

    .line 100
    goto/16 :goto_8

    .line 101
    .line 102
    :cond_4
    const/4 p1, 0x0

    .line 103
    if-ne p0, v9, :cond_d

    .line 104
    .line 105
    invoke-virtual {v3}, Lxy0/j;->w()J

    .line 106
    .line 107
    .line 108
    move-result-wide v9

    .line 109
    cmp-long p0, v6, v9

    .line 110
    .line 111
    if-gez p0, :cond_5

    .line 112
    .line 113
    invoke-virtual {v4}, Laz0/c;->b()V

    .line 114
    .line 115
    .line 116
    :cond_5
    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    check-cast p0, Lxy0/r;

    .line 121
    .line 122
    :goto_3
    invoke-virtual {v3}, Lxy0/j;->A()Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-eqz v0, :cond_6

    .line 127
    .line 128
    invoke-virtual {v3}, Lxy0/j;->t()Ljava/lang/Throwable;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-virtual {v8, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 137
    .line 138
    .line 139
    goto/16 :goto_7

    .line 140
    .line 141
    :cond_6
    move-object v10, v8

    .line 142
    :try_start_1
    invoke-virtual {v2, v3}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 143
    .line 144
    .line 145
    move-result-wide v8

    .line 146
    sget v0, Lxy0/l;->b:I

    .line 147
    .line 148
    int-to-long v0, v0

    .line 149
    div-long v4, v8, v0

    .line 150
    .line 151
    rem-long v0, v8, v0

    .line 152
    .line 153
    long-to-int v7, v0

    .line 154
    iget-wide v0, p0, Laz0/q;->f:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 155
    .line 156
    cmp-long v0, v0, v4

    .line 157
    .line 158
    if-eqz v0, :cond_8

    .line 159
    .line 160
    :try_start_2
    invoke-virtual {v3, v4, v5, p0}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 161
    .line 162
    .line 163
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 164
    if-nez v0, :cond_7

    .line 165
    .line 166
    move-object v8, v10

    .line 167
    goto :goto_3

    .line 168
    :cond_7
    move-object v6, v0

    .line 169
    :goto_4
    move-object v5, v3

    .line 170
    goto :goto_5

    .line 171
    :catchall_1
    move-exception v0

    .line 172
    move-object p0, v0

    .line 173
    move-object v8, v10

    .line 174
    goto :goto_8

    .line 175
    :cond_8
    move-object v6, p0

    .line 176
    goto :goto_4

    .line 177
    :goto_5
    :try_start_3
    invoke-virtual/range {v5 .. v10}, Lxy0/j;->L(Lxy0/r;IJLjava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 181
    move-object v3, v5

    .line 182
    move-object v0, v6

    .line 183
    move-wide v4, v8

    .line 184
    move-object v8, v10

    .line 185
    :try_start_4
    sget-object v1, Lxy0/l;->m:Lj51/i;

    .line 186
    .line 187
    if-ne p0, v1, :cond_9

    .line 188
    .line 189
    invoke-virtual {v8, v0, v7}, Lvy0/l;->b(Laz0/q;I)V

    .line 190
    .line 191
    .line 192
    goto :goto_7

    .line 193
    :cond_9
    sget-object v1, Lxy0/l;->o:Lj51/i;

    .line 194
    .line 195
    if-ne p0, v1, :cond_b

    .line 196
    .line 197
    invoke-virtual {v3}, Lxy0/j;->w()J

    .line 198
    .line 199
    .line 200
    move-result-wide v6

    .line 201
    cmp-long p0, v4, v6

    .line 202
    .line 203
    if-gez p0, :cond_a

    .line 204
    .line 205
    invoke-virtual {v0}, Laz0/c;->b()V

    .line 206
    .line 207
    .line 208
    :cond_a
    move-object p0, v0

    .line 209
    goto :goto_3

    .line 210
    :cond_b
    sget-object v1, Lxy0/l;->n:Lj51/i;

    .line 211
    .line 212
    if-eq p0, v1, :cond_c

    .line 213
    .line 214
    invoke-virtual {v0}, Laz0/c;->b()V

    .line 215
    .line 216
    .line 217
    goto :goto_6

    .line 218
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 219
    .line 220
    invoke-direct {p0, v11}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    throw p0

    .line 224
    :catchall_2
    move-exception v0

    .line 225
    move-object v8, v10

    .line 226
    goto :goto_2

    .line 227
    :cond_d
    invoke-virtual {v4}, Laz0/c;->b()V

    .line 228
    .line 229
    .line 230
    :goto_6
    invoke-virtual {v8, p0, p1}, Lvy0/l;->t(Ljava/lang/Object;Lay0/o;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 231
    .line 232
    .line 233
    :goto_7
    invoke-virtual {v8}, Lvy0/l;->p()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 238
    .line 239
    return-object p0

    .line 240
    :goto_8
    invoke-virtual {v8}, Lvy0/l;->B()V

    .line 241
    .line 242
    .line 243
    throw p0

    .line 244
    :cond_e
    invoke-virtual {v4}, Laz0/c;->b()V

    .line 245
    .line 246
    .line 247
    return-object p0

    .line 248
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 249
    .line 250
    invoke-direct {p0, v11}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    throw p0

    .line 254
    :cond_10
    move-object v3, p0

    .line 255
    invoke-virtual {v3}, Lxy0/j;->t()Ljava/lang/Throwable;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    sget p1, Laz0/r;->a:I

    .line 260
    .line 261
    throw p0
.end method

.method public final s()Ljava/lang/Throwable;
    .locals 1

    .line 1
    sget-object v0, Lxy0/j;->l:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Throwable;

    .line 8
    .line 9
    return-object p0
.end method

.method public final t()Ljava/lang/Throwable;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    new-instance p0, Lxy0/s;

    .line 8
    .line 9
    const-string v0, "Channel was closed"

    .line 10
    .line 11
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 6
    .line 7
    .line 8
    sget-object v2, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 9
    .line 10
    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    const/16 v4, 0x3c

    .line 15
    .line 16
    shr-long/2addr v2, v4

    .line 17
    long-to-int v2, v2

    .line 18
    const/4 v3, 0x3

    .line 19
    const/4 v4, 0x2

    .line 20
    if-eq v2, v4, :cond_1

    .line 21
    .line 22
    if-eq v2, v3, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const-string v2, "cancelled,"

    .line 26
    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const-string v2, "closed,"

    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    :goto_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    const-string v5, "capacity="

    .line 39
    .line 40
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget v5, v0, Lxy0/j;->d:I

    .line 44
    .line 45
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const/16 v5, 0x2c

    .line 49
    .line 50
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v2, "data=["

    .line 61
    .line 62
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    new-array v2, v3, [Lxy0/r;

    .line 66
    .line 67
    sget-object v3, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 68
    .line 69
    invoke-virtual {v3, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const/4 v6, 0x0

    .line 74
    aput-object v3, v2, v6

    .line 75
    .line 76
    sget-object v3, Lxy0/j;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 77
    .line 78
    invoke-virtual {v3, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    const/4 v7, 0x1

    .line 83
    aput-object v3, v2, v7

    .line 84
    .line 85
    sget-object v3, Lxy0/j;->k:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 86
    .line 87
    invoke-virtual {v3, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    aput-object v3, v2, v4

    .line 92
    .line 93
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    check-cast v2, Ljava/lang/Iterable;

    .line 98
    .line 99
    new-instance v3, Ljava/util/ArrayList;

    .line 100
    .line 101
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 102
    .line 103
    .line 104
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    :cond_2
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    if-eqz v4, :cond_3

    .line 113
    .line 114
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    move-object v8, v4

    .line 119
    check-cast v8, Lxy0/r;

    .line 120
    .line 121
    sget-object v9, Lxy0/l;->a:Lxy0/r;

    .line 122
    .line 123
    if-eq v8, v9, :cond_2

    .line 124
    .line 125
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_3
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v3

    .line 137
    if-eqz v3, :cond_19

    .line 138
    .line 139
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    if-nez v4, :cond_4

    .line 148
    .line 149
    goto :goto_2

    .line 150
    :cond_4
    move-object v4, v3

    .line 151
    check-cast v4, Lxy0/r;

    .line 152
    .line 153
    iget-wide v8, v4, Laz0/q;->f:J

    .line 154
    .line 155
    :cond_5
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    move-object v10, v4

    .line 160
    check-cast v10, Lxy0/r;

    .line 161
    .line 162
    iget-wide v10, v10, Laz0/q;->f:J

    .line 163
    .line 164
    cmp-long v12, v8, v10

    .line 165
    .line 166
    if-lez v12, :cond_6

    .line 167
    .line 168
    move-object v3, v4

    .line 169
    move-wide v8, v10

    .line 170
    :cond_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v4

    .line 174
    if-nez v4, :cond_5

    .line 175
    .line 176
    :goto_2
    check-cast v3, Lxy0/r;

    .line 177
    .line 178
    sget-object v2, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 179
    .line 180
    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 181
    .line 182
    .line 183
    move-result-wide v10

    .line 184
    invoke-virtual {v0}, Lxy0/j;->w()J

    .line 185
    .line 186
    .line 187
    move-result-wide v12

    .line 188
    :goto_3
    sget v0, Lxy0/l;->b:I

    .line 189
    .line 190
    move v2, v6

    .line 191
    :goto_4
    if-ge v2, v0, :cond_15

    .line 192
    .line 193
    iget-wide v8, v3, Laz0/q;->f:J

    .line 194
    .line 195
    sget v4, Lxy0/l;->b:I

    .line 196
    .line 197
    int-to-long v14, v4

    .line 198
    mul-long/2addr v8, v14

    .line 199
    int-to-long v14, v2

    .line 200
    add-long/2addr v8, v14

    .line 201
    cmp-long v4, v8, v12

    .line 202
    .line 203
    if-ltz v4, :cond_7

    .line 204
    .line 205
    cmp-long v14, v8, v10

    .line 206
    .line 207
    if-gez v14, :cond_16

    .line 208
    .line 209
    :cond_7
    invoke-virtual {v3, v2}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v14

    .line 213
    iget-object v15, v3, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 214
    .line 215
    mul-int/lit8 v6, v2, 0x2

    .line 216
    .line 217
    invoke-virtual {v15, v6}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v6

    .line 221
    instance-of v15, v14, Lvy0/k;

    .line 222
    .line 223
    if-eqz v15, :cond_a

    .line 224
    .line 225
    cmp-long v8, v8, v10

    .line 226
    .line 227
    if-gez v8, :cond_8

    .line 228
    .line 229
    if-ltz v4, :cond_8

    .line 230
    .line 231
    const-string v4, "receive"

    .line 232
    .line 233
    goto/16 :goto_6

    .line 234
    .line 235
    :cond_8
    if-gez v4, :cond_9

    .line 236
    .line 237
    if-ltz v8, :cond_9

    .line 238
    .line 239
    const-string v4, "send"

    .line 240
    .line 241
    goto/16 :goto_6

    .line 242
    .line 243
    :cond_9
    const-string v4, "cont"

    .line 244
    .line 245
    goto/16 :goto_6

    .line 246
    .line 247
    :cond_a
    instance-of v15, v14, Ldz0/f;

    .line 248
    .line 249
    if-eqz v15, :cond_d

    .line 250
    .line 251
    cmp-long v8, v8, v10

    .line 252
    .line 253
    if-gez v8, :cond_b

    .line 254
    .line 255
    if-ltz v4, :cond_b

    .line 256
    .line 257
    const-string v4, "onReceive"

    .line 258
    .line 259
    goto/16 :goto_6

    .line 260
    .line 261
    :cond_b
    if-gez v4, :cond_c

    .line 262
    .line 263
    if-ltz v8, :cond_c

    .line 264
    .line 265
    const-string v4, "onSend"

    .line 266
    .line 267
    goto/16 :goto_6

    .line 268
    .line 269
    :cond_c
    const-string v4, "select"

    .line 270
    .line 271
    goto/16 :goto_6

    .line 272
    .line 273
    :cond_d
    instance-of v4, v14, Lxy0/y;

    .line 274
    .line 275
    if-eqz v4, :cond_e

    .line 276
    .line 277
    const-string v4, "receiveCatching"

    .line 278
    .line 279
    goto :goto_6

    .line 280
    :cond_e
    instance-of v4, v14, Lxy0/b0;

    .line 281
    .line 282
    if-eqz v4, :cond_f

    .line 283
    .line 284
    new-instance v4, Ljava/lang/StringBuilder;

    .line 285
    .line 286
    const-string v8, "EB("

    .line 287
    .line 288
    invoke-direct {v4, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    invoke-virtual {v4, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 292
    .line 293
    .line 294
    const/16 v8, 0x29

    .line 295
    .line 296
    invoke-virtual {v4, v8}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 297
    .line 298
    .line 299
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object v4

    .line 303
    goto :goto_6

    .line 304
    :cond_f
    sget-object v4, Lxy0/l;->f:Lj51/i;

    .line 305
    .line 306
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    move-result v4

    .line 310
    if-nez v4, :cond_12

    .line 311
    .line 312
    sget-object v4, Lxy0/l;->g:Lj51/i;

    .line 313
    .line 314
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    if-eqz v4, :cond_10

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_10
    if-eqz v14, :cond_14

    .line 322
    .line 323
    sget-object v4, Lxy0/l;->e:Lj51/i;

    .line 324
    .line 325
    invoke-virtual {v14, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v4

    .line 329
    if-nez v4, :cond_14

    .line 330
    .line 331
    sget-object v4, Lxy0/l;->i:Lj51/i;

    .line 332
    .line 333
    invoke-virtual {v14, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 334
    .line 335
    .line 336
    move-result v4

    .line 337
    if-nez v4, :cond_14

    .line 338
    .line 339
    sget-object v4, Lxy0/l;->h:Lj51/i;

    .line 340
    .line 341
    invoke-virtual {v14, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    move-result v4

    .line 345
    if-nez v4, :cond_14

    .line 346
    .line 347
    sget-object v4, Lxy0/l;->k:Lj51/i;

    .line 348
    .line 349
    invoke-virtual {v14, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 350
    .line 351
    .line 352
    move-result v4

    .line 353
    if-nez v4, :cond_14

    .line 354
    .line 355
    sget-object v4, Lxy0/l;->j:Lj51/i;

    .line 356
    .line 357
    invoke-virtual {v14, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 358
    .line 359
    .line 360
    move-result v4

    .line 361
    if-nez v4, :cond_14

    .line 362
    .line 363
    sget-object v4, Lxy0/l;->l:Lj51/i;

    .line 364
    .line 365
    invoke-virtual {v14, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 366
    .line 367
    .line 368
    move-result v4

    .line 369
    if-eqz v4, :cond_11

    .line 370
    .line 371
    goto :goto_7

    .line 372
    :cond_11
    invoke-virtual {v14}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object v4

    .line 376
    goto :goto_6

    .line 377
    :cond_12
    :goto_5
    const-string v4, "resuming_sender"

    .line 378
    .line 379
    :goto_6
    if-eqz v6, :cond_13

    .line 380
    .line 381
    new-instance v8, Ljava/lang/StringBuilder;

    .line 382
    .line 383
    const-string v9, "("

    .line 384
    .line 385
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 389
    .line 390
    .line 391
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 392
    .line 393
    .line 394
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 395
    .line 396
    .line 397
    const-string v4, "),"

    .line 398
    .line 399
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 400
    .line 401
    .line 402
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 403
    .line 404
    .line 405
    move-result-object v4

    .line 406
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 407
    .line 408
    .line 409
    goto :goto_7

    .line 410
    :cond_13
    new-instance v6, Ljava/lang/StringBuilder;

    .line 411
    .line 412
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 413
    .line 414
    .line 415
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 416
    .line 417
    .line 418
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 419
    .line 420
    .line 421
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v4

    .line 425
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 426
    .line 427
    .line 428
    :cond_14
    :goto_7
    add-int/lit8 v2, v2, 0x1

    .line 429
    .line 430
    const/4 v6, 0x0

    .line 431
    goto/16 :goto_4

    .line 432
    .line 433
    :cond_15
    invoke-virtual {v3}, Laz0/c;->c()Laz0/c;

    .line 434
    .line 435
    .line 436
    move-result-object v0

    .line 437
    move-object v3, v0

    .line 438
    check-cast v3, Lxy0/r;

    .line 439
    .line 440
    if-nez v3, :cond_18

    .line 441
    .line 442
    :cond_16
    invoke-static {v1}, Lly0/p;->N(Ljava/lang/CharSequence;)C

    .line 443
    .line 444
    .line 445
    move-result v0

    .line 446
    if-ne v0, v5, :cond_17

    .line 447
    .line 448
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->length()I

    .line 449
    .line 450
    .line 451
    move-result v0

    .line 452
    sub-int/2addr v0, v7

    .line 453
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->deleteCharAt(I)Ljava/lang/StringBuilder;

    .line 454
    .line 455
    .line 456
    move-result-object v0

    .line 457
    const-string v2, "deleteCharAt(...)"

    .line 458
    .line 459
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    :cond_17
    const-string v0, "]"

    .line 463
    .line 464
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 465
    .line 466
    .line 467
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    return-object v0

    .line 472
    :cond_18
    const/4 v6, 0x0

    .line 473
    goto/16 :goto_3

    .line 474
    .line 475
    :cond_19
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 476
    .line 477
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 478
    .line 479
    .line 480
    throw v0
.end method

.method public u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v8, Lxy0/j;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 4
    .line 5
    invoke-virtual {v8, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Lxy0/r;

    .line 10
    .line 11
    :cond_0
    :goto_0
    sget-object v9, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 12
    .line 13
    invoke-virtual {v9, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    const-wide v10, 0xfffffffffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long v4, v2, v10

    .line 23
    .line 24
    const/4 v12, 0x0

    .line 25
    invoke-virtual {v0, v2, v3, v12}, Lxy0/j;->z(JZ)Z

    .line 26
    .line 27
    .line 28
    move-result v7

    .line 29
    sget v13, Lxy0/l;->b:I

    .line 30
    .line 31
    int-to-long v2, v13

    .line 32
    div-long v14, v4, v2

    .line 33
    .line 34
    rem-long v2, v4, v2

    .line 35
    .line 36
    long-to-int v2, v2

    .line 37
    move-wide/from16 v16, v10

    .line 38
    .line 39
    iget-wide v10, v1, Laz0/q;->f:J

    .line 40
    .line 41
    cmp-long v3, v10, v14

    .line 42
    .line 43
    sget-object v10, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    if-eqz v3, :cond_2

    .line 46
    .line 47
    invoke-static {v0, v14, v15, v1}, Lxy0/j;->a(Lxy0/j;JLxy0/r;)Lxy0/r;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    if-nez v3, :cond_1

    .line 52
    .line 53
    if-eqz v7, :cond_0

    .line 54
    .line 55
    invoke-virtual/range {p0 .. p2}, Lxy0/j;->F(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 60
    .line 61
    if-ne v0, v1, :cond_18

    .line 62
    .line 63
    return-object v0

    .line 64
    :cond_1
    move-object v1, v3

    .line 65
    :cond_2
    const/4 v6, 0x0

    .line 66
    move-object/from16 v3, p1

    .line 67
    .line 68
    invoke-static/range {v0 .. v7}, Lxy0/j;->f(Lxy0/j;Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-eqz v6, :cond_19

    .line 73
    .line 74
    const/4 v11, 0x1

    .line 75
    if-eq v6, v11, :cond_18

    .line 76
    .line 77
    const/4 v14, 0x2

    .line 78
    if-eq v6, v14, :cond_17

    .line 79
    .line 80
    sget-object v15, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 81
    .line 82
    const/4 v3, 0x5

    .line 83
    const/4 v7, 0x4

    .line 84
    const/4 v12, 0x3

    .line 85
    if-eq v6, v12, :cond_6

    .line 86
    .line 87
    if-eq v6, v7, :cond_4

    .line 88
    .line 89
    if-eq v6, v3, :cond_3

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_3
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_4
    invoke-virtual {v15, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 97
    .line 98
    .line 99
    move-result-wide v2

    .line 100
    cmp-long v2, v4, v2

    .line 101
    .line 102
    if-gez v2, :cond_5

    .line 103
    .line 104
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 105
    .line 106
    .line 107
    :cond_5
    invoke-virtual/range {p0 .. p2}, Lxy0/j;->F(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 112
    .line 113
    if-ne v0, v1, :cond_18

    .line 114
    .line 115
    return-object v0

    .line 116
    :cond_6
    invoke-static/range {p2 .. p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    invoke-static {v6}, Lvy0/e0;->x(Lkotlin/coroutines/Continuation;)Lvy0/l;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    move/from16 v18, v7

    .line 125
    .line 126
    const/4 v7, 0x0

    .line 127
    move-object/from16 v3, p1

    .line 128
    .line 129
    move/from16 v12, v18

    .line 130
    .line 131
    :try_start_0
    invoke-static/range {v0 .. v7}, Lxy0/j;->f(Lxy0/j;Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I

    .line 132
    .line 133
    .line 134
    move-result v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 135
    if-eqz v7, :cond_15

    .line 136
    .line 137
    if-eq v7, v11, :cond_10

    .line 138
    .line 139
    if-eq v7, v14, :cond_14

    .line 140
    .line 141
    if-eq v7, v12, :cond_13

    .line 142
    .line 143
    const-string v13, "unexpected"

    .line 144
    .line 145
    const/4 v2, 0x5

    .line 146
    if-ne v7, v2, :cond_12

    .line 147
    .line 148
    :try_start_1
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v8, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    check-cast v1, Lxy0/r;

    .line 156
    .line 157
    :goto_1
    invoke-virtual {v9, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndIncrement(Ljava/lang/Object;)J

    .line 158
    .line 159
    .line 160
    move-result-wide v4

    .line 161
    and-long v7, v4, v16

    .line 162
    .line 163
    const/4 v2, 0x0

    .line 164
    invoke-virtual {v0, v4, v5, v2}, Lxy0/j;->z(JZ)Z

    .line 165
    .line 166
    .line 167
    move-result v4

    .line 168
    sget v5, Lxy0/l;->b:I

    .line 169
    .line 170
    move-object/from16 p2, v13

    .line 171
    .line 172
    int-to-long v12, v5

    .line 173
    move-object/from16 v19, v15

    .line 174
    .line 175
    div-long v14, v7, v12

    .line 176
    .line 177
    rem-long v12, v7, v12

    .line 178
    .line 179
    long-to-int v12, v12

    .line 180
    move v13, v12

    .line 181
    iget-wide v11, v1, Laz0/q;->f:J

    .line 182
    .line 183
    cmp-long v11, v11, v14

    .line 184
    .line 185
    if-eqz v11, :cond_a

    .line 186
    .line 187
    invoke-static {v0, v14, v15, v1}, Lxy0/j;->a(Lxy0/j;JLxy0/r;)Lxy0/r;

    .line 188
    .line 189
    .line 190
    move-result-object v11

    .line 191
    if-nez v11, :cond_9

    .line 192
    .line 193
    if-eqz v4, :cond_8

    .line 194
    .line 195
    :cond_7
    :goto_2
    invoke-static {v0, v3, v6}, Lxy0/j;->b(Lxy0/j;Ljava/lang/Object;Lvy0/l;)V

    .line 196
    .line 197
    .line 198
    goto/16 :goto_5

    .line 199
    .line 200
    :catchall_0
    move-exception v0

    .line 201
    goto/16 :goto_7

    .line 202
    .line 203
    :cond_8
    move-object/from16 v13, p2

    .line 204
    .line 205
    move-object/from16 v15, v19

    .line 206
    .line 207
    const/4 v11, 0x1

    .line 208
    const/4 v12, 0x4

    .line 209
    const/4 v14, 0x2

    .line 210
    goto :goto_1

    .line 211
    :cond_9
    move-object v1, v11

    .line 212
    :cond_a
    move v11, v2

    .line 213
    move v2, v13

    .line 214
    move-wide/from16 v20, v7

    .line 215
    .line 216
    move v7, v4

    .line 217
    move v8, v5

    .line 218
    move-wide/from16 v4, v20

    .line 219
    .line 220
    invoke-static/range {v0 .. v7}, Lxy0/j;->f(Lxy0/j;Lxy0/r;ILjava/lang/Object;JLjava/lang/Object;Z)I

    .line 221
    .line 222
    .line 223
    move-result v12

    .line 224
    move v13, v2

    .line 225
    if-eqz v12, :cond_11

    .line 226
    .line 227
    const/4 v2, 0x1

    .line 228
    if-eq v12, v2, :cond_10

    .line 229
    .line 230
    const/4 v14, 0x2

    .line 231
    if-eq v12, v14, :cond_e

    .line 232
    .line 233
    const/4 v15, 0x3

    .line 234
    if-eq v12, v15, :cond_d

    .line 235
    .line 236
    const/4 v7, 0x4

    .line 237
    if-eq v12, v7, :cond_c

    .line 238
    .line 239
    const/4 v8, 0x5

    .line 240
    if-eq v12, v8, :cond_b

    .line 241
    .line 242
    goto :goto_3

    .line 243
    :cond_b
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 244
    .line 245
    .line 246
    :goto_3
    move-object/from16 v13, p2

    .line 247
    .line 248
    move v11, v2

    .line 249
    move v12, v7

    .line 250
    move-object/from16 v15, v19

    .line 251
    .line 252
    goto :goto_1

    .line 253
    :cond_c
    move-object/from16 v2, v19

    .line 254
    .line 255
    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 256
    .line 257
    .line 258
    move-result-wide v7

    .line 259
    cmp-long v2, v4, v7

    .line 260
    .line 261
    if-gez v2, :cond_7

    .line 262
    .line 263
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 264
    .line 265
    .line 266
    goto :goto_2

    .line 267
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    move-object/from16 v1, p2

    .line 270
    .line 271
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw v0

    .line 275
    :cond_e
    if-eqz v7, :cond_f

    .line 276
    .line 277
    invoke-virtual {v1}, Laz0/q;->i()V

    .line 278
    .line 279
    .line 280
    goto :goto_2

    .line 281
    :cond_f
    add-int v12, v13, v8

    .line 282
    .line 283
    invoke-virtual {v6, v1, v12}, Lvy0/l;->b(Laz0/q;I)V

    .line 284
    .line 285
    .line 286
    goto :goto_5

    .line 287
    :cond_10
    :goto_4
    invoke-virtual {v6, v10}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    goto :goto_5

    .line 291
    :cond_11
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 292
    .line 293
    .line 294
    goto :goto_4

    .line 295
    :cond_12
    move-object v1, v13

    .line 296
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 297
    .line 298
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    throw v0

    .line 302
    :cond_13
    move-object v2, v15

    .line 303
    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 304
    .line 305
    .line 306
    move-result-wide v7

    .line 307
    cmp-long v2, v4, v7

    .line 308
    .line 309
    if-gez v2, :cond_7

    .line 310
    .line 311
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 312
    .line 313
    .line 314
    goto :goto_2

    .line 315
    :cond_14
    add-int/2addr v2, v13

    .line 316
    invoke-virtual {v6, v1, v2}, Lvy0/l;->b(Laz0/q;I)V

    .line 317
    .line 318
    .line 319
    goto :goto_5

    .line 320
    :cond_15
    invoke-virtual {v1}, Laz0/c;->b()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 321
    .line 322
    .line 323
    goto :goto_4

    .line 324
    :goto_5
    invoke-virtual {v6}, Lvy0/l;->p()Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 329
    .line 330
    if-ne v0, v1, :cond_16

    .line 331
    .line 332
    goto :goto_6

    .line 333
    :cond_16
    move-object v0, v10

    .line 334
    :goto_6
    if-ne v0, v1, :cond_18

    .line 335
    .line 336
    return-object v0

    .line 337
    :goto_7
    invoke-virtual {v6}, Lvy0/l;->B()V

    .line 338
    .line 339
    .line 340
    throw v0

    .line 341
    :cond_17
    move-object/from16 v3, p1

    .line 342
    .line 343
    if-eqz v7, :cond_18

    .line 344
    .line 345
    invoke-virtual {v1}, Laz0/q;->i()V

    .line 346
    .line 347
    .line 348
    invoke-virtual/range {p0 .. p2}, Lxy0/j;->F(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v0

    .line 352
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 353
    .line 354
    if-ne v0, v1, :cond_18

    .line 355
    .line 356
    return-object v0

    .line 357
    :cond_18
    return-object v10

    .line 358
    :cond_19
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 359
    .line 360
    .line 361
    return-object v10
.end method

.method public final v()Ljava/lang/Throwable;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lxy0/j;->s()Ljava/lang/Throwable;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    new-instance p0, Lxy0/t;

    .line 8
    .line 9
    const-string v0, "Channel was closed"

    .line 10
    .line 11
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-object p0
.end method

.method public final w()J
    .locals 4

    .line 1
    sget-object v0, Lxy0/j;->e:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide v2, 0xfffffffffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr v0, v2

    .line 13
    return-wide v0
.end method

.method public final x()Z
    .locals 11

    .line 1
    :cond_0
    :goto_0
    sget-object v0, Lxy0/j;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lxy0/r;

    .line 8
    .line 9
    sget-object v2, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 10
    .line 11
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 12
    .line 13
    .line 14
    move-result-wide v5

    .line 15
    invoke-virtual {p0}, Lxy0/j;->w()J

    .line 16
    .line 17
    .line 18
    move-result-wide v3

    .line 19
    cmp-long v3, v3, v5

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    if-gtz v3, :cond_1

    .line 23
    .line 24
    return v4

    .line 25
    :cond_1
    sget v3, Lxy0/l;->b:I

    .line 26
    .line 27
    int-to-long v7, v3

    .line 28
    div-long v7, v5, v7

    .line 29
    .line 30
    iget-wide v9, v1, Laz0/q;->f:J

    .line 31
    .line 32
    cmp-long v9, v9, v7

    .line 33
    .line 34
    if-eqz v9, :cond_2

    .line 35
    .line 36
    invoke-virtual {p0, v7, v8, v1}, Lxy0/j;->q(JLxy0/r;)Lxy0/r;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    if-nez v1, :cond_2

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Lxy0/r;

    .line 47
    .line 48
    iget-wide v0, v0, Laz0/q;->f:J

    .line 49
    .line 50
    cmp-long v0, v0, v7

    .line 51
    .line 52
    if-gez v0, :cond_0

    .line 53
    .line 54
    return v4

    .line 55
    :cond_2
    invoke-virtual {v1}, Laz0/c;->b()V

    .line 56
    .line 57
    .line 58
    int-to-long v3, v3

    .line 59
    rem-long v3, v5, v3

    .line 60
    .line 61
    long-to-int v0, v3

    .line 62
    :cond_3
    invoke-virtual {v1, v0}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    if-eqz v3, :cond_c

    .line 67
    .line 68
    sget-object v4, Lxy0/l;->e:Lj51/i;

    .line 69
    .line 70
    if-ne v3, v4, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    sget-object v0, Lxy0/l;->d:Lj51/i;

    .line 74
    .line 75
    if-ne v3, v0, :cond_5

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_5
    sget-object v0, Lxy0/l;->j:Lj51/i;

    .line 79
    .line 80
    if-ne v3, v0, :cond_6

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_6
    sget-object v0, Lxy0/l;->l:Lj51/i;

    .line 84
    .line 85
    if-ne v3, v0, :cond_7

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_7
    sget-object v0, Lxy0/l;->i:Lj51/i;

    .line 89
    .line 90
    if-ne v3, v0, :cond_8

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_8
    sget-object v0, Lxy0/l;->h:Lj51/i;

    .line 94
    .line 95
    if-ne v3, v0, :cond_9

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_9
    sget-object v0, Lxy0/l;->g:Lj51/i;

    .line 99
    .line 100
    if-ne v3, v0, :cond_a

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_a
    sget-object v0, Lxy0/l;->f:Lj51/i;

    .line 104
    .line 105
    if-ne v3, v0, :cond_b

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_b
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 109
    .line 110
    .line 111
    move-result-wide v0

    .line 112
    cmp-long v0, v5, v0

    .line 113
    .line 114
    if-nez v0, :cond_d

    .line 115
    .line 116
    :goto_1
    const/4 p0, 0x1

    .line 117
    return p0

    .line 118
    :cond_c
    :goto_2
    sget-object v4, Lxy0/l;->h:Lj51/i;

    .line 119
    .line 120
    invoke-virtual {v1, v0, v3, v4}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    if-eqz v3, :cond_3

    .line 125
    .line 126
    invoke-virtual {p0}, Lxy0/j;->p()V

    .line 127
    .line 128
    .line 129
    :cond_d
    :goto_3
    const-wide/16 v0, 0x1

    .line 130
    .line 131
    add-long v7, v5, v0

    .line 132
    .line 133
    sget-object v3, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 134
    .line 135
    move-object v4, p0

    .line 136
    invoke-virtual/range {v3 .. v8}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 137
    .line 138
    .line 139
    goto/16 :goto_0
.end method

.method public final z(JZ)Z
    .locals 9

    .line 1
    const/16 v0, 0x3c

    .line 2
    .line 3
    shr-long v0, p1, v0

    .line 4
    .line 5
    long-to-int v0, v0

    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_f

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v0, v2, :cond_f

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    const-wide v4, 0xfffffffffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    if-eq v0, v3, :cond_d

    .line 19
    .line 20
    const/4 p3, 0x3

    .line 21
    if-ne v0, p3, :cond_c

    .line 22
    .line 23
    and-long/2addr p1, v4

    .line 24
    invoke-virtual {p0, p1, p2}, Lxy0/j;->k(J)Lxy0/r;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const/4 p2, 0x0

    .line 29
    move-object p3, p2

    .line 30
    :cond_0
    sget v0, Lxy0/l;->b:I

    .line 31
    .line 32
    sub-int/2addr v0, v2

    .line 33
    :goto_0
    const/4 v3, -0x1

    .line 34
    if-ge v3, v0, :cond_9

    .line 35
    .line 36
    iget-wide v4, p1, Laz0/q;->f:J

    .line 37
    .line 38
    sget v6, Lxy0/l;->b:I

    .line 39
    .line 40
    int-to-long v6, v6

    .line 41
    mul-long/2addr v4, v6

    .line 42
    int-to-long v6, v0

    .line 43
    add-long/2addr v4, v6

    .line 44
    :cond_1
    invoke-virtual {p1, v0}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    sget-object v7, Lxy0/l;->i:Lj51/i;

    .line 49
    .line 50
    if-eq v6, v7, :cond_a

    .line 51
    .line 52
    sget-object v7, Lxy0/l;->d:Lj51/i;

    .line 53
    .line 54
    sget-object v8, Lxy0/j;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 55
    .line 56
    if-ne v6, v7, :cond_2

    .line 57
    .line 58
    invoke-virtual {v8, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 59
    .line 60
    .line 61
    move-result-wide v7

    .line 62
    cmp-long v7, v4, v7

    .line 63
    .line 64
    if-ltz v7, :cond_a

    .line 65
    .line 66
    sget-object v7, Lxy0/l;->l:Lj51/i;

    .line 67
    .line 68
    invoke-virtual {p1, v0, v6, v7}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-eqz v6, :cond_1

    .line 73
    .line 74
    invoke-virtual {p1, v0, p2}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1}, Laz0/q;->i()V

    .line 78
    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_2
    sget-object v7, Lxy0/l;->e:Lj51/i;

    .line 82
    .line 83
    if-eq v6, v7, :cond_8

    .line 84
    .line 85
    if-nez v6, :cond_3

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_3
    instance-of v7, v6, Lvy0/k2;

    .line 89
    .line 90
    if-nez v7, :cond_6

    .line 91
    .line 92
    instance-of v7, v6, Lxy0/b0;

    .line 93
    .line 94
    if-eqz v7, :cond_4

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_4
    sget-object v7, Lxy0/l;->g:Lj51/i;

    .line 98
    .line 99
    if-eq v6, v7, :cond_a

    .line 100
    .line 101
    sget-object v8, Lxy0/l;->f:Lj51/i;

    .line 102
    .line 103
    if-ne v6, v8, :cond_5

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_5
    if-eq v6, v7, :cond_1

    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_6
    :goto_1
    invoke-virtual {v8, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 110
    .line 111
    .line 112
    move-result-wide v7

    .line 113
    cmp-long v7, v4, v7

    .line 114
    .line 115
    if-ltz v7, :cond_a

    .line 116
    .line 117
    instance-of v7, v6, Lxy0/b0;

    .line 118
    .line 119
    if-eqz v7, :cond_7

    .line 120
    .line 121
    move-object v7, v6

    .line 122
    check-cast v7, Lxy0/b0;

    .line 123
    .line 124
    iget-object v7, v7, Lxy0/b0;->a:Lvy0/k2;

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_7
    move-object v7, v6

    .line 128
    check-cast v7, Lvy0/k2;

    .line 129
    .line 130
    :goto_2
    sget-object v8, Lxy0/l;->l:Lj51/i;

    .line 131
    .line 132
    invoke-virtual {p1, v0, v6, v8}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v6

    .line 136
    if-eqz v6, :cond_1

    .line 137
    .line 138
    invoke-static {p3, v7}, Laz0/b;->f(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p3

    .line 142
    invoke-virtual {p1, v0, p2}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p1}, Laz0/q;->i()V

    .line 146
    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_8
    :goto_3
    sget-object v7, Lxy0/l;->l:Lj51/i;

    .line 150
    .line 151
    invoke-virtual {p1, v0, v6, v7}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v6

    .line 155
    if-eqz v6, :cond_1

    .line 156
    .line 157
    invoke-virtual {p1}, Laz0/q;->i()V

    .line 158
    .line 159
    .line 160
    :goto_4
    add-int/lit8 v0, v0, -0x1

    .line 161
    .line 162
    goto/16 :goto_0

    .line 163
    .line 164
    :cond_9
    sget-object v0, Laz0/c;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 165
    .line 166
    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    check-cast p1, Laz0/c;

    .line 171
    .line 172
    check-cast p1, Lxy0/r;

    .line 173
    .line 174
    if-nez p1, :cond_0

    .line 175
    .line 176
    :cond_a
    :goto_5
    if-eqz p3, :cond_e

    .line 177
    .line 178
    instance-of p1, p3, Ljava/util/ArrayList;

    .line 179
    .line 180
    if-nez p1, :cond_b

    .line 181
    .line 182
    check-cast p3, Lvy0/k2;

    .line 183
    .line 184
    invoke-virtual {p0, p3, v1}, Lxy0/j;->I(Lvy0/k2;Z)V

    .line 185
    .line 186
    .line 187
    goto :goto_7

    .line 188
    :cond_b
    check-cast p3, Ljava/util/ArrayList;

    .line 189
    .line 190
    invoke-virtual {p3}, Ljava/util/ArrayList;->size()I

    .line 191
    .line 192
    .line 193
    move-result p1

    .line 194
    sub-int/2addr p1, v2

    .line 195
    :goto_6
    if-ge v3, p1, :cond_e

    .line 196
    .line 197
    invoke-virtual {p3, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p2

    .line 201
    check-cast p2, Lvy0/k2;

    .line 202
    .line 203
    invoke-virtual {p0, p2, v1}, Lxy0/j;->I(Lvy0/k2;Z)V

    .line 204
    .line 205
    .line 206
    add-int/lit8 p1, p1, -0x1

    .line 207
    .line 208
    goto :goto_6

    .line 209
    :cond_c
    const-string p0, "unexpected close status: "

    .line 210
    .line 211
    invoke-static {v0, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 216
    .line 217
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw p1

    .line 225
    :cond_d
    and-long/2addr p1, v4

    .line 226
    invoke-virtual {p0, p1, p2}, Lxy0/j;->k(J)Lxy0/r;

    .line 227
    .line 228
    .line 229
    if-eqz p3, :cond_e

    .line 230
    .line 231
    invoke-virtual {p0}, Lxy0/j;->x()Z

    .line 232
    .line 233
    .line 234
    move-result p0

    .line 235
    if-nez p0, :cond_f

    .line 236
    .line 237
    :cond_e
    :goto_7
    return v2

    .line 238
    :cond_f
    return v1
.end method

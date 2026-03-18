.class public final Lcz0/a;
.super Ljava/lang/Thread;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic l:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final d:Lcz0/m;

.field public final e:Lkotlin/jvm/internal/f0;

.field public f:Lcz0/b;

.field public g:J

.field public h:J

.field public i:I

.field private volatile indexInArray:I

.field public j:Z

.field public final synthetic k:Lcz0/c;

.field private volatile nextParkedWorker:Ljava/lang/Object;

.field private volatile synthetic workerCtl$volatile:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lcz0/a;

    .line 2
    .line 3
    const-string v1, "workerCtl$volatile"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lcz0/a;->l:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lcz0/c;I)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcz0/a;->k:Lcz0/c;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Thread;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/Thread;->setDaemon(Z)V

    .line 8
    .line 9
    .line 10
    const-class p1, Lcz0/c;

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/Thread;->setContextClassLoader(Ljava/lang/ClassLoader;)V

    .line 17
    .line 18
    .line 19
    new-instance p1, Lcz0/m;

    .line 20
    .line 21
    invoke-direct {p1}, Lcz0/m;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lcz0/a;->d:Lcz0/m;

    .line 25
    .line 26
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 27
    .line 28
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lcz0/a;->e:Lkotlin/jvm/internal/f0;

    .line 32
    .line 33
    sget-object p1, Lcz0/b;->g:Lcz0/b;

    .line 34
    .line 35
    iput-object p1, p0, Lcz0/a;->f:Lcz0/b;

    .line 36
    .line 37
    sget-object p1, Lcz0/c;->n:Lj51/i;

    .line 38
    .line 39
    iput-object p1, p0, Lcz0/a;->nextParkedWorker:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 42
    .line 43
    .line 44
    move-result-wide v0

    .line 45
    long-to-int p1, v0

    .line 46
    if-eqz p1, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    const/16 p1, 0x2a

    .line 50
    .line 51
    :goto_0
    iput p1, p0, Lcz0/a;->i:I

    .line 52
    .line 53
    invoke-virtual {p0, p2}, Lcz0/a;->f(I)V

    .line 54
    .line 55
    .line 56
    return-void
.end method


# virtual methods
.method public final a(Z)Lcz0/i;
    .locals 11

    .line 1
    iget-object v0, p0, Lcz0/a;->f:Lcz0/b;

    .line 2
    .line 3
    sget-object v1, Lcz0/b;->d:Lcz0/b;

    .line 4
    .line 5
    iget-object v3, p0, Lcz0/a;->k:Lcz0/c;

    .line 6
    .line 7
    const/4 v8, 0x0

    .line 8
    const/4 v9, 0x1

    .line 9
    iget-object v10, p0, Lcz0/a;->d:Lcz0/m;

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    goto/16 :goto_3

    .line 14
    .line 15
    :cond_0
    sget-object v0, Lcz0/c;->l:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 16
    .line 17
    :cond_1
    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v4

    .line 21
    const-wide v1, 0x7ffffc0000000000L

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    and-long/2addr v1, v4

    .line 27
    const/16 v6, 0x2a

    .line 28
    .line 29
    shr-long/2addr v1, v6

    .line 30
    long-to-int v1, v1

    .line 31
    if-nez v1, :cond_b

    .line 32
    .line 33
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p1, Lcz0/m;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 37
    .line 38
    invoke-virtual {p1, v10}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Lcz0/i;

    .line 43
    .line 44
    if-nez v0, :cond_2

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    iget-boolean v1, v0, Lcz0/i;->e:Z

    .line 48
    .line 49
    if-ne v1, v9, :cond_5

    .line 50
    .line 51
    :cond_3
    invoke-virtual {p1, v10, v0, v8}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_4

    .line 56
    .line 57
    move-object v8, v0

    .line 58
    goto :goto_2

    .line 59
    :cond_4
    invoke-virtual {p1, v10}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    if-eq v1, v0, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_5
    :goto_1
    sget-object p1, Lcz0/m;->d:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 67
    .line 68
    invoke-virtual {p1, v10}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    sget-object v0, Lcz0/m;->c:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 73
    .line 74
    invoke-virtual {v0, v10}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    :cond_6
    if-eq p1, v0, :cond_8

    .line 79
    .line 80
    sget-object v1, Lcz0/m;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 81
    .line 82
    invoke-virtual {v1, v10}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-nez v1, :cond_7

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_7
    add-int/lit8 v0, v0, -0x1

    .line 90
    .line 91
    invoke-virtual {v10, v0, v9}, Lcz0/m;->c(IZ)Lcz0/i;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    if-eqz v1, :cond_6

    .line 96
    .line 97
    move-object v8, v1

    .line 98
    :cond_8
    :goto_2
    if-nez v8, :cond_a

    .line 99
    .line 100
    iget-object p1, v3, Lcz0/c;->i:Lcz0/f;

    .line 101
    .line 102
    invoke-virtual {p1}, Laz0/j;->d()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    check-cast p1, Lcz0/i;

    .line 107
    .line 108
    if-nez p1, :cond_9

    .line 109
    .line 110
    invoke-virtual {p0, v9}, Lcz0/a;->i(I)Lcz0/i;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :cond_9
    return-object p1

    .line 116
    :cond_a
    return-object v8

    .line 117
    :cond_b
    const-wide v1, 0x40000000000L

    .line 118
    .line 119
    .line 120
    .line 121
    .line 122
    sub-long v6, v4, v1

    .line 123
    .line 124
    sget-object v2, Lcz0/c;->l:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 125
    .line 126
    invoke-virtual/range {v2 .. v7}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-eqz v1, :cond_1

    .line 131
    .line 132
    sget-object v0, Lcz0/b;->d:Lcz0/b;

    .line 133
    .line 134
    iput-object v0, p0, Lcz0/a;->f:Lcz0/b;

    .line 135
    .line 136
    :goto_3
    if-eqz p1, :cond_10

    .line 137
    .line 138
    iget p1, v3, Lcz0/c;->d:I

    .line 139
    .line 140
    mul-int/lit8 p1, p1, 0x2

    .line 141
    .line 142
    invoke-virtual {p0, p1}, Lcz0/a;->d(I)I

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    if-nez p1, :cond_c

    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_c
    const/4 v9, 0x0

    .line 150
    :goto_4
    if-eqz v9, :cond_d

    .line 151
    .line 152
    invoke-virtual {p0}, Lcz0/a;->e()Lcz0/i;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    if-eqz p1, :cond_d

    .line 157
    .line 158
    return-object p1

    .line 159
    :cond_d
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    sget-object p1, Lcz0/m;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 163
    .line 164
    invoke-virtual {p1, v10, v8}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->getAndSet(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    check-cast p1, Lcz0/i;

    .line 169
    .line 170
    if-nez p1, :cond_e

    .line 171
    .line 172
    invoke-virtual {v10}, Lcz0/m;->b()Lcz0/i;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    :cond_e
    if-eqz p1, :cond_f

    .line 177
    .line 178
    return-object p1

    .line 179
    :cond_f
    if-nez v9, :cond_11

    .line 180
    .line 181
    invoke-virtual {p0}, Lcz0/a;->e()Lcz0/i;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    if-eqz p1, :cond_11

    .line 186
    .line 187
    return-object p1

    .line 188
    :cond_10
    invoke-virtual {p0}, Lcz0/a;->e()Lcz0/i;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    if-eqz p1, :cond_11

    .line 193
    .line 194
    return-object p1

    .line 195
    :cond_11
    const/4 p1, 0x3

    .line 196
    invoke-virtual {p0, p1}, Lcz0/a;->i(I)Lcz0/i;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    return-object p0
.end method

.method public final b()I
    .locals 0

    .line 1
    iget p0, p0, Lcz0/a;->indexInArray:I

    .line 2
    .line 3
    return p0
.end method

.method public final c()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz0/a;->nextParkedWorker:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(I)I
    .locals 2

    .line 1
    iget v0, p0, Lcz0/a;->i:I

    .line 2
    .line 3
    shl-int/lit8 v1, v0, 0xd

    .line 4
    .line 5
    xor-int/2addr v0, v1

    .line 6
    shr-int/lit8 v1, v0, 0x11

    .line 7
    .line 8
    xor-int/2addr v0, v1

    .line 9
    shl-int/lit8 v1, v0, 0x5

    .line 10
    .line 11
    xor-int/2addr v0, v1

    .line 12
    iput v0, p0, Lcz0/a;->i:I

    .line 13
    .line 14
    add-int/lit8 p0, p1, -0x1

    .line 15
    .line 16
    and-int v1, p0, p1

    .line 17
    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    and-int/2addr p0, v0

    .line 21
    return p0

    .line 22
    :cond_0
    const p0, 0x7fffffff

    .line 23
    .line 24
    .line 25
    and-int/2addr p0, v0

    .line 26
    rem-int/2addr p0, p1

    .line 27
    return p0
.end method

.method public final e()Lcz0/i;
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Lcz0/a;->d(I)I

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    iget-object p0, p0, Lcz0/a;->k:Lcz0/c;

    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    iget-object v0, p0, Lcz0/c;->h:Lcz0/f;

    .line 11
    .line 12
    invoke-virtual {v0}, Laz0/j;->d()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lcz0/i;

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    return-object v0

    .line 21
    :cond_0
    iget-object p0, p0, Lcz0/c;->i:Lcz0/f;

    .line 22
    .line 23
    invoke-virtual {p0}, Laz0/j;->d()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lcz0/i;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_1
    iget-object v0, p0, Lcz0/c;->i:Lcz0/f;

    .line 31
    .line 32
    invoke-virtual {v0}, Laz0/j;->d()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Lcz0/i;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    return-object v0

    .line 41
    :cond_2
    iget-object p0, p0, Lcz0/c;->h:Lcz0/f;

    .line 42
    .line 43
    invoke-virtual {p0}, Laz0/j;->d()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lcz0/i;

    .line 48
    .line 49
    return-object p0
.end method

.method public final f(I)V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcz0/a;->k:Lcz0/c;

    .line 7
    .line 8
    iget-object v1, v1, Lcz0/c;->g:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, "-worker-"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    const-string v1, "TERMINATED"

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {p0, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iput p1, p0, Lcz0/a;->indexInArray:I

    .line 38
    .line 39
    return-void
.end method

.method public final g(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcz0/a;->nextParkedWorker:Ljava/lang/Object;

    .line 2
    .line 3
    return-void
.end method

.method public final h(Lcz0/b;)Z
    .locals 6

    .line 1
    iget-object v0, p0, Lcz0/a;->f:Lcz0/b;

    .line 2
    .line 3
    sget-object v1, Lcz0/b;->d:Lcz0/b;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v1, 0x0

    .line 10
    :goto_0
    if-eqz v1, :cond_1

    .line 11
    .line 12
    sget-object v2, Lcz0/c;->l:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 13
    .line 14
    const-wide v3, 0x40000000000L

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    iget-object v5, p0, Lcz0/a;->k:Lcz0/c;

    .line 20
    .line 21
    invoke-virtual {v2, v5, v3, v4}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->addAndGet(Ljava/lang/Object;J)J

    .line 22
    .line 23
    .line 24
    :cond_1
    if-eq v0, p1, :cond_2

    .line 25
    .line 26
    iput-object p1, p0, Lcz0/a;->f:Lcz0/b;

    .line 27
    .line 28
    :cond_2
    return v1
.end method

.method public final i(I)Lcz0/i;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    sget-object v2, Lcz0/c;->l:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 6
    .line 7
    iget-object v3, v0, Lcz0/a;->k:Lcz0/c;

    .line 8
    .line 9
    invoke-virtual {v2, v3}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 10
    .line 11
    .line 12
    move-result-wide v4

    .line 13
    const-wide/32 v6, 0x1fffff

    .line 14
    .line 15
    .line 16
    and-long/2addr v4, v6

    .line 17
    long-to-int v2, v4

    .line 18
    const/4 v4, 0x0

    .line 19
    const/4 v5, 0x2

    .line 20
    if-ge v2, v5, :cond_0

    .line 21
    .line 22
    return-object v4

    .line 23
    :cond_0
    invoke-virtual {v0, v2}, Lcz0/a;->d(I)I

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    const/4 v10, 0x0

    .line 28
    const-wide v11, 0x7fffffffffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    :goto_0
    if-ge v10, v2, :cond_11

    .line 34
    .line 35
    const/4 v15, 0x1

    .line 36
    add-int/2addr v6, v15

    .line 37
    if-le v6, v2, :cond_1

    .line 38
    .line 39
    move v6, v15

    .line 40
    :cond_1
    iget-object v5, v3, Lcz0/c;->j:Laz0/o;

    .line 41
    .line 42
    invoke-virtual {v5, v6}, Laz0/o;->b(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    check-cast v5, Lcz0/a;

    .line 47
    .line 48
    if-eqz v5, :cond_f

    .line 49
    .line 50
    if-eq v5, v0, :cond_f

    .line 51
    .line 52
    iget-object v5, v5, Lcz0/a;->d:Lcz0/m;

    .line 53
    .line 54
    const/4 v7, 0x3

    .line 55
    if-ne v1, v7, :cond_2

    .line 56
    .line 57
    invoke-virtual {v5}, Lcz0/m;->b()Lcz0/i;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    const-wide v16, 0x7fffffffffffffffL

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    const-wide/16 v18, 0x0

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_2
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    sget-object v7, Lcz0/m;->d:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 73
    .line 74
    invoke-virtual {v7, v5}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    const-wide v16, 0x7fffffffffffffffL

    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    sget-object v8, Lcz0/m;->c:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 84
    .line 85
    invoke-virtual {v8, v5}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 86
    .line 87
    .line 88
    move-result v8

    .line 89
    if-ne v1, v15, :cond_3

    .line 90
    .line 91
    move v9, v15

    .line 92
    goto :goto_1

    .line 93
    :cond_3
    const/4 v9, 0x0

    .line 94
    :goto_1
    if-eq v7, v8, :cond_5

    .line 95
    .line 96
    const-wide/16 v18, 0x0

    .line 97
    .line 98
    if-eqz v9, :cond_4

    .line 99
    .line 100
    sget-object v13, Lcz0/m;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 101
    .line 102
    invoke-virtual {v13, v5}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 103
    .line 104
    .line 105
    move-result v13

    .line 106
    if-nez v13, :cond_4

    .line 107
    .line 108
    :goto_2
    move-object v7, v4

    .line 109
    goto :goto_3

    .line 110
    :cond_4
    add-int/lit8 v13, v7, 0x1

    .line 111
    .line 112
    invoke-virtual {v5, v7, v9}, Lcz0/m;->c(IZ)Lcz0/i;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    if-nez v7, :cond_6

    .line 117
    .line 118
    move v7, v13

    .line 119
    goto :goto_1

    .line 120
    :cond_5
    const-wide/16 v18, 0x0

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_6
    :goto_3
    iget-object v13, v0, Lcz0/a;->e:Lkotlin/jvm/internal/f0;

    .line 124
    .line 125
    if-eqz v7, :cond_7

    .line 126
    .line 127
    iput-object v7, v13, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 128
    .line 129
    move-object v5, v4

    .line 130
    const-wide/16 v7, -0x1

    .line 131
    .line 132
    const-wide/16 v20, -0x1

    .line 133
    .line 134
    goto :goto_7

    .line 135
    :cond_7
    :goto_4
    sget-object v7, Lcz0/m;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 136
    .line 137
    invoke-virtual {v7, v5}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v14

    .line 141
    check-cast v14, Lcz0/i;

    .line 142
    .line 143
    if-nez v14, :cond_8

    .line 144
    .line 145
    const-wide/16 v20, -0x1

    .line 146
    .line 147
    goto :goto_6

    .line 148
    :cond_8
    const-wide/16 v20, -0x1

    .line 149
    .line 150
    iget-boolean v8, v14, Lcz0/i;->e:Z

    .line 151
    .line 152
    if-eqz v8, :cond_9

    .line 153
    .line 154
    move v8, v15

    .line 155
    goto :goto_5

    .line 156
    :cond_9
    const/4 v8, 0x2

    .line 157
    :goto_5
    and-int/2addr v8, v1

    .line 158
    if-nez v8, :cond_a

    .line 159
    .line 160
    :goto_6
    const-wide/16 v7, -0x2

    .line 161
    .line 162
    move-object v5, v4

    .line 163
    goto :goto_7

    .line 164
    :cond_a
    sget-object v8, Lcz0/k;->f:Lcz0/g;

    .line 165
    .line 166
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 170
    .line 171
    .line 172
    move-result-wide v8

    .line 173
    move-object/from16 v23, v5

    .line 174
    .line 175
    iget-wide v4, v14, Lcz0/i;->d:J

    .line 176
    .line 177
    sub-long/2addr v8, v4

    .line 178
    sget-wide v4, Lcz0/k;->b:J

    .line 179
    .line 180
    cmp-long v24, v8, v4

    .line 181
    .line 182
    if-gez v24, :cond_b

    .line 183
    .line 184
    sub-long v7, v4, v8

    .line 185
    .line 186
    const/4 v5, 0x0

    .line 187
    goto :goto_7

    .line 188
    :cond_b
    move-object/from16 v4, v23

    .line 189
    .line 190
    :cond_c
    const/4 v5, 0x0

    .line 191
    invoke-virtual {v7, v4, v14, v5}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result v8

    .line 195
    if-eqz v8, :cond_e

    .line 196
    .line 197
    iput-object v14, v13, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 198
    .line 199
    move-wide/from16 v7, v20

    .line 200
    .line 201
    :goto_7
    cmp-long v4, v7, v20

    .line 202
    .line 203
    if-nez v4, :cond_d

    .line 204
    .line 205
    iget-object v0, v13, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 206
    .line 207
    check-cast v0, Lcz0/i;

    .line 208
    .line 209
    iput-object v5, v13, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 210
    .line 211
    return-object v0

    .line 212
    :cond_d
    cmp-long v4, v7, v18

    .line 213
    .line 214
    if-lez v4, :cond_10

    .line 215
    .line 216
    invoke-static {v11, v12, v7, v8}, Ljava/lang/Math;->min(JJ)J

    .line 217
    .line 218
    .line 219
    move-result-wide v11

    .line 220
    goto :goto_8

    .line 221
    :cond_e
    invoke-virtual {v7, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    if-eq v5, v14, :cond_c

    .line 226
    .line 227
    move-object v5, v4

    .line 228
    const/4 v4, 0x0

    .line 229
    goto :goto_4

    .line 230
    :cond_f
    const-wide v16, 0x7fffffffffffffffL

    .line 231
    .line 232
    .line 233
    .line 234
    .line 235
    :cond_10
    :goto_8
    add-int/lit8 v10, v10, 0x1

    .line 236
    .line 237
    const/4 v4, 0x0

    .line 238
    const/4 v5, 0x2

    .line 239
    goto/16 :goto_0

    .line 240
    .line 241
    :cond_11
    const-wide v16, 0x7fffffffffffffffL

    .line 242
    .line 243
    .line 244
    .line 245
    .line 246
    const-wide/16 v18, 0x0

    .line 247
    .line 248
    cmp-long v1, v11, v16

    .line 249
    .line 250
    if-eqz v1, :cond_12

    .line 251
    .line 252
    goto :goto_9

    .line 253
    :cond_12
    move-wide/from16 v11, v18

    .line 254
    .line 255
    :goto_9
    iput-wide v11, v0, Lcz0/a;->h:J

    .line 256
    .line 257
    const/16 v22, 0x0

    .line 258
    .line 259
    return-object v22
.end method

.method public final run()V
    .locals 23

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    :cond_0
    :goto_0
    move v0, v2

    .line 5
    :cond_1
    :goto_1
    iget-object v3, v1, Lcz0/a;->k:Lcz0/c;

    .line 6
    .line 7
    sget-object v4, Lcz0/c;->m:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 8
    .line 9
    invoke-virtual {v4, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    const/4 v4, 0x1

    .line 14
    if-ne v3, v4, :cond_2

    .line 15
    .line 16
    goto/16 :goto_a

    .line 17
    .line 18
    :cond_2
    iget-object v3, v1, Lcz0/a;->f:Lcz0/b;

    .line 19
    .line 20
    sget-object v5, Lcz0/b;->h:Lcz0/b;

    .line 21
    .line 22
    if-eq v3, v5, :cond_17

    .line 23
    .line 24
    iget-boolean v3, v1, Lcz0/a;->j:Z

    .line 25
    .line 26
    invoke-virtual {v1, v3}, Lcz0/a;->a(Z)Lcz0/i;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    const-wide/32 v6, -0x200000

    .line 31
    .line 32
    .line 33
    const-wide/16 v8, 0x0

    .line 34
    .line 35
    if-eqz v3, :cond_8

    .line 36
    .line 37
    iput-wide v8, v1, Lcz0/a;->h:J

    .line 38
    .line 39
    iget-object v4, v1, Lcz0/a;->k:Lcz0/c;

    .line 40
    .line 41
    iput-wide v8, v1, Lcz0/a;->g:J

    .line 42
    .line 43
    iget-object v0, v1, Lcz0/a;->f:Lcz0/b;

    .line 44
    .line 45
    sget-object v8, Lcz0/b;->f:Lcz0/b;

    .line 46
    .line 47
    if-ne v0, v8, :cond_3

    .line 48
    .line 49
    sget-object v0, Lcz0/b;->e:Lcz0/b;

    .line 50
    .line 51
    iput-object v0, v1, Lcz0/a;->f:Lcz0/b;

    .line 52
    .line 53
    :cond_3
    iget-boolean v0, v3, Lcz0/i;->e:Z

    .line 54
    .line 55
    if-eqz v0, :cond_7

    .line 56
    .line 57
    sget-object v0, Lcz0/b;->e:Lcz0/b;

    .line 58
    .line 59
    invoke-virtual {v1, v0}, Lcz0/a;->h(Lcz0/b;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_6

    .line 64
    .line 65
    invoke-virtual {v4}, Lcz0/c;->h()Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-eqz v0, :cond_4

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_4
    sget-object v0, Lcz0/c;->l:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 73
    .line 74
    invoke-virtual {v0, v4}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 75
    .line 76
    .line 77
    move-result-wide v8

    .line 78
    invoke-virtual {v4, v8, v9}, Lcz0/c;->g(J)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_5

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_5
    invoke-virtual {v4}, Lcz0/c;->h()Z

    .line 86
    .line 87
    .line 88
    :cond_6
    :goto_2
    :try_start_0
    invoke-interface {v3}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :catchall_0
    move-exception v0

    .line 93
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    invoke-virtual {v3}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    .line 98
    .line 99
    .line 100
    move-result-object v8

    .line 101
    invoke-interface {v8, v3, v0}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    .line 102
    .line 103
    .line 104
    :goto_3
    sget-object v0, Lcz0/c;->l:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 105
    .line 106
    invoke-virtual {v0, v4, v6, v7}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->addAndGet(Ljava/lang/Object;J)J

    .line 107
    .line 108
    .line 109
    iget-object v0, v1, Lcz0/a;->f:Lcz0/b;

    .line 110
    .line 111
    if-eq v0, v5, :cond_0

    .line 112
    .line 113
    sget-object v0, Lcz0/b;->g:Lcz0/b;

    .line 114
    .line 115
    iput-object v0, v1, Lcz0/a;->f:Lcz0/b;

    .line 116
    .line 117
    goto :goto_0

    .line 118
    :cond_7
    :try_start_1
    invoke-interface {v3}, Ljava/lang/Runnable;->run()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :catchall_1
    move-exception v0

    .line 123
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    invoke-virtual {v3}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    invoke-interface {v4, v3, v0}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    .line 132
    .line 133
    .line 134
    goto/16 :goto_0

    .line 135
    .line 136
    :cond_8
    iput-boolean v2, v1, Lcz0/a;->j:Z

    .line 137
    .line 138
    iget-wide v10, v1, Lcz0/a;->h:J

    .line 139
    .line 140
    cmp-long v3, v10, v8

    .line 141
    .line 142
    if-eqz v3, :cond_a

    .line 143
    .line 144
    if-nez v0, :cond_9

    .line 145
    .line 146
    move v0, v4

    .line 147
    goto/16 :goto_1

    .line 148
    .line 149
    :cond_9
    sget-object v0, Lcz0/b;->f:Lcz0/b;

    .line 150
    .line 151
    invoke-virtual {v1, v0}, Lcz0/a;->h(Lcz0/b;)Z

    .line 152
    .line 153
    .line 154
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 155
    .line 156
    .line 157
    iget-wide v3, v1, Lcz0/a;->h:J

    .line 158
    .line 159
    invoke-static {v3, v4}, Ljava/util/concurrent/locks/LockSupport;->parkNanos(J)V

    .line 160
    .line 161
    .line 162
    iput-wide v8, v1, Lcz0/a;->h:J

    .line 163
    .line 164
    goto/16 :goto_0

    .line 165
    .line 166
    :cond_a
    iget-object v3, v1, Lcz0/a;->nextParkedWorker:Ljava/lang/Object;

    .line 167
    .line 168
    sget-object v5, Lcz0/c;->n:Lj51/i;

    .line 169
    .line 170
    if-eq v3, v5, :cond_14

    .line 171
    .line 172
    sget-object v3, Lcz0/a;->l:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 173
    .line 174
    const/4 v5, -0x1

    .line 175
    invoke-virtual {v3, v1, v5}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->set(Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    :cond_b
    :goto_4
    iget-object v3, v1, Lcz0/a;->nextParkedWorker:Ljava/lang/Object;

    .line 179
    .line 180
    sget-object v6, Lcz0/c;->n:Lj51/i;

    .line 181
    .line 182
    if-eq v3, v6, :cond_1

    .line 183
    .line 184
    sget-object v3, Lcz0/a;->l:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 185
    .line 186
    invoke-virtual {v3, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 187
    .line 188
    .line 189
    move-result v6

    .line 190
    if-ne v6, v5, :cond_1

    .line 191
    .line 192
    iget-object v6, v1, Lcz0/a;->k:Lcz0/c;

    .line 193
    .line 194
    sget-object v7, Lcz0/c;->m:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 195
    .line 196
    invoke-virtual {v7, v6}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 197
    .line 198
    .line 199
    move-result v6

    .line 200
    if-ne v6, v4, :cond_c

    .line 201
    .line 202
    goto/16 :goto_1

    .line 203
    .line 204
    :cond_c
    iget-object v6, v1, Lcz0/a;->f:Lcz0/b;

    .line 205
    .line 206
    sget-object v12, Lcz0/b;->h:Lcz0/b;

    .line 207
    .line 208
    if-ne v6, v12, :cond_d

    .line 209
    .line 210
    goto/16 :goto_1

    .line 211
    .line 212
    :cond_d
    sget-object v6, Lcz0/b;->f:Lcz0/b;

    .line 213
    .line 214
    invoke-virtual {v1, v6}, Lcz0/a;->h(Lcz0/b;)Z

    .line 215
    .line 216
    .line 217
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 218
    .line 219
    .line 220
    iget-wide v13, v1, Lcz0/a;->g:J

    .line 221
    .line 222
    cmp-long v6, v13, v8

    .line 223
    .line 224
    if-nez v6, :cond_e

    .line 225
    .line 226
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 227
    .line 228
    .line 229
    move-result-wide v13

    .line 230
    iget-object v6, v1, Lcz0/a;->k:Lcz0/c;

    .line 231
    .line 232
    const-wide/32 v15, 0x1fffff

    .line 233
    .line 234
    .line 235
    iget-wide v10, v6, Lcz0/c;->f:J

    .line 236
    .line 237
    add-long/2addr v13, v10

    .line 238
    iput-wide v13, v1, Lcz0/a;->g:J

    .line 239
    .line 240
    goto :goto_5

    .line 241
    :cond_e
    const-wide/32 v15, 0x1fffff

    .line 242
    .line 243
    .line 244
    :goto_5
    iget-object v6, v1, Lcz0/a;->k:Lcz0/c;

    .line 245
    .line 246
    iget-wide v10, v6, Lcz0/c;->f:J

    .line 247
    .line 248
    invoke-static {v10, v11}, Ljava/util/concurrent/locks/LockSupport;->parkNanos(J)V

    .line 249
    .line 250
    .line 251
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 252
    .line 253
    .line 254
    move-result-wide v10

    .line 255
    iget-wide v13, v1, Lcz0/a;->g:J

    .line 256
    .line 257
    sub-long/2addr v10, v13

    .line 258
    cmp-long v6, v10, v8

    .line 259
    .line 260
    if-ltz v6, :cond_b

    .line 261
    .line 262
    iput-wide v8, v1, Lcz0/a;->g:J

    .line 263
    .line 264
    iget-object v6, v1, Lcz0/a;->k:Lcz0/c;

    .line 265
    .line 266
    iget-object v10, v6, Lcz0/c;->j:Laz0/o;

    .line 267
    .line 268
    monitor-enter v10

    .line 269
    :try_start_2
    invoke-virtual {v7, v6}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 270
    .line 271
    .line 272
    move-result v7
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 273
    if-ne v7, v4, :cond_f

    .line 274
    .line 275
    move v7, v4

    .line 276
    goto :goto_6

    .line 277
    :cond_f
    move v7, v2

    .line 278
    :goto_6
    if-eqz v7, :cond_10

    .line 279
    .line 280
    monitor-exit v10

    .line 281
    goto :goto_4

    .line 282
    :cond_10
    :try_start_3
    sget-object v7, Lcz0/c;->l:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 283
    .line 284
    invoke-virtual {v7, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 285
    .line 286
    .line 287
    move-result-wide v13

    .line 288
    and-long/2addr v13, v15

    .line 289
    long-to-int v11, v13

    .line 290
    iget v13, v6, Lcz0/c;->d:I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 291
    .line 292
    if-gt v11, v13, :cond_11

    .line 293
    .line 294
    monitor-exit v10

    .line 295
    goto :goto_4

    .line 296
    :cond_11
    :try_start_4
    invoke-virtual {v3, v1, v5, v4}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    .line 297
    .line 298
    .line 299
    move-result v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 300
    if-nez v3, :cond_12

    .line 301
    .line 302
    monitor-exit v10

    .line 303
    goto :goto_4

    .line 304
    :cond_12
    :try_start_5
    iget v3, v1, Lcz0/a;->indexInArray:I

    .line 305
    .line 306
    invoke-virtual {v1, v2}, Lcz0/a;->f(I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v6, v1, v3, v2}, Lcz0/c;->f(Lcz0/a;II)V

    .line 310
    .line 311
    .line 312
    invoke-virtual {v7, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndDecrement(Ljava/lang/Object;)J

    .line 313
    .line 314
    .line 315
    move-result-wide v13

    .line 316
    and-long/2addr v13, v15

    .line 317
    long-to-int v7, v13

    .line 318
    if-eq v7, v3, :cond_13

    .line 319
    .line 320
    iget-object v11, v6, Lcz0/c;->j:Laz0/o;

    .line 321
    .line 322
    invoke-virtual {v11, v7}, Laz0/o;->b(I)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object v11

    .line 326
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 327
    .line 328
    .line 329
    check-cast v11, Lcz0/a;

    .line 330
    .line 331
    iget-object v13, v6, Lcz0/c;->j:Laz0/o;

    .line 332
    .line 333
    invoke-virtual {v13, v3, v11}, Laz0/o;->c(ILcz0/a;)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {v11, v3}, Lcz0/a;->f(I)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v6, v11, v7, v3}, Lcz0/c;->f(Lcz0/a;II)V

    .line 340
    .line 341
    .line 342
    goto :goto_7

    .line 343
    :catchall_2
    move-exception v0

    .line 344
    goto :goto_8

    .line 345
    :cond_13
    :goto_7
    iget-object v3, v6, Lcz0/c;->j:Laz0/o;

    .line 346
    .line 347
    const/4 v6, 0x0

    .line 348
    invoke-virtual {v3, v7, v6}, Laz0/o;->c(ILcz0/a;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 349
    .line 350
    .line 351
    monitor-exit v10

    .line 352
    iput-object v12, v1, Lcz0/a;->f:Lcz0/b;

    .line 353
    .line 354
    goto/16 :goto_4

    .line 355
    .line 356
    :goto_8
    monitor-exit v10

    .line 357
    throw v0

    .line 358
    :cond_14
    const-wide/32 v15, 0x1fffff

    .line 359
    .line 360
    .line 361
    iget-object v3, v1, Lcz0/a;->k:Lcz0/c;

    .line 362
    .line 363
    iget-object v4, v1, Lcz0/a;->nextParkedWorker:Ljava/lang/Object;

    .line 364
    .line 365
    if-eq v4, v5, :cond_15

    .line 366
    .line 367
    goto/16 :goto_1

    .line 368
    .line 369
    :cond_15
    sget-object v4, Lcz0/c;->k:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 370
    .line 371
    :goto_9
    invoke-virtual {v4, v3}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 372
    .line 373
    .line 374
    move-result-wide v19

    .line 375
    and-long v8, v19, v15

    .line 376
    .line 377
    long-to-int v5, v8

    .line 378
    const-wide/32 v8, 0x200000

    .line 379
    .line 380
    .line 381
    add-long v8, v19, v8

    .line 382
    .line 383
    and-long/2addr v8, v6

    .line 384
    iget v10, v1, Lcz0/a;->indexInArray:I

    .line 385
    .line 386
    iget-object v11, v3, Lcz0/c;->j:Laz0/o;

    .line 387
    .line 388
    invoke-virtual {v11, v5}, Laz0/o;->b(I)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v5

    .line 392
    iput-object v5, v1, Lcz0/a;->nextParkedWorker:Ljava/lang/Object;

    .line 393
    .line 394
    sget-object v17, Lcz0/c;->k:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 395
    .line 396
    int-to-long v10, v10

    .line 397
    or-long v21, v8, v10

    .line 398
    .line 399
    move-object/from16 v18, v3

    .line 400
    .line 401
    invoke-virtual/range {v17 .. v22}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 402
    .line 403
    .line 404
    move-result v3

    .line 405
    if-eqz v3, :cond_16

    .line 406
    .line 407
    goto/16 :goto_1

    .line 408
    .line 409
    :cond_16
    move-object/from16 v3, v18

    .line 410
    .line 411
    goto :goto_9

    .line 412
    :cond_17
    :goto_a
    sget-object v0, Lcz0/b;->h:Lcz0/b;

    .line 413
    .line 414
    invoke-virtual {v1, v0}, Lcz0/a;->h(Lcz0/b;)Z

    .line 415
    .line 416
    .line 417
    return-void
.end method

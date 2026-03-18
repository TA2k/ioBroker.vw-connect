.class public final Lu01/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final d:Lu01/t;

.field public e:J

.field public f:Z


# direct methods
.method public constructor <init>(Lu01/t;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu01/j;->d:Lu01/t;

    .line 5
    .line 6
    iput-wide p2, p0, Lu01/j;->e:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-wide/from16 v2, p2

    .line 6
    .line 7
    const-string v4, "sink"

    .line 8
    .line 9
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-boolean v4, v0, Lu01/j;->f:Z

    .line 13
    .line 14
    if-nez v4, :cond_8

    .line 15
    .line 16
    iget-object v4, v0, Lu01/j;->d:Lu01/t;

    .line 17
    .line 18
    iget-wide v5, v0, Lu01/j;->e:J

    .line 19
    .line 20
    const-wide/16 v7, 0x0

    .line 21
    .line 22
    cmp-long v7, v2, v7

    .line 23
    .line 24
    if-ltz v7, :cond_7

    .line 25
    .line 26
    add-long/2addr v2, v5

    .line 27
    move-wide v7, v5

    .line 28
    :goto_0
    cmp-long v9, v7, v2

    .line 29
    .line 30
    if-gez v9, :cond_4

    .line 31
    .line 32
    const/4 v9, 0x1

    .line 33
    invoke-virtual {v1, v9}, Lu01/f;->W(I)Lu01/c0;

    .line 34
    .line 35
    .line 36
    move-result-object v9

    .line 37
    iget-object v12, v9, Lu01/c0;->a:[B

    .line 38
    .line 39
    iget v13, v9, Lu01/c0;->c:I

    .line 40
    .line 41
    sub-long v14, v2, v7

    .line 42
    .line 43
    const-wide/16 p2, -0x1

    .line 44
    .line 45
    rsub-int v10, v13, 0x2000

    .line 46
    .line 47
    int-to-long v10, v10

    .line 48
    invoke-static {v14, v15, v10, v11}, Ljava/lang/Math;->min(JJ)J

    .line 49
    .line 50
    .line 51
    move-result-wide v10

    .line 52
    long-to-int v10, v10

    .line 53
    monitor-enter v4

    .line 54
    :try_start_0
    const-string v11, "array"

    .line 55
    .line 56
    invoke-static {v12, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v11, v4, Lu01/t;->g:Ljava/io/RandomAccessFile;

    .line 60
    .line 61
    invoke-virtual {v11, v7, v8}, Ljava/io/RandomAccessFile;->seek(J)V

    .line 62
    .line 63
    .line 64
    const/4 v11, 0x0

    .line 65
    :goto_1
    if-ge v11, v10, :cond_1

    .line 66
    .line 67
    iget-object v15, v4, Lu01/t;->g:Ljava/io/RandomAccessFile;

    .line 68
    .line 69
    sub-int v14, v10, v11

    .line 70
    .line 71
    invoke-virtual {v15, v12, v13, v14}, Ljava/io/RandomAccessFile;->read([BII)I

    .line 72
    .line 73
    .line 74
    move-result v14
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    const/4 v15, -0x1

    .line 76
    if-ne v14, v15, :cond_0

    .line 77
    .line 78
    if-nez v11, :cond_1

    .line 79
    .line 80
    monitor-exit v4

    .line 81
    const/4 v11, -0x1

    .line 82
    :goto_2
    const/4 v15, -0x1

    .line 83
    goto :goto_3

    .line 84
    :cond_0
    add-int/2addr v11, v14

    .line 85
    goto :goto_1

    .line 86
    :catchall_0
    move-exception v0

    .line 87
    goto :goto_4

    .line 88
    :cond_1
    monitor-exit v4

    .line 89
    goto :goto_2

    .line 90
    :goto_3
    if-ne v11, v15, :cond_3

    .line 91
    .line 92
    iget v2, v9, Lu01/c0;->b:I

    .line 93
    .line 94
    iget v3, v9, Lu01/c0;->c:I

    .line 95
    .line 96
    if-ne v2, v3, :cond_2

    .line 97
    .line 98
    invoke-virtual {v9}, Lu01/c0;->a()Lu01/c0;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    iput-object v2, v1, Lu01/f;->d:Lu01/c0;

    .line 103
    .line 104
    invoke-static {v9}, Lu01/d0;->a(Lu01/c0;)V

    .line 105
    .line 106
    .line 107
    :cond_2
    cmp-long v1, v5, v7

    .line 108
    .line 109
    if-nez v1, :cond_5

    .line 110
    .line 111
    move-wide/from16 v7, p2

    .line 112
    .line 113
    goto :goto_5

    .line 114
    :cond_3
    iget v10, v9, Lu01/c0;->c:I

    .line 115
    .line 116
    add-int/2addr v10, v11

    .line 117
    iput v10, v9, Lu01/c0;->c:I

    .line 118
    .line 119
    int-to-long v9, v11

    .line 120
    add-long/2addr v7, v9

    .line 121
    iget-wide v11, v1, Lu01/f;->e:J

    .line 122
    .line 123
    add-long/2addr v11, v9

    .line 124
    iput-wide v11, v1, Lu01/f;->e:J

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :goto_4
    :try_start_1
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 128
    throw v0

    .line 129
    :cond_4
    const-wide/16 p2, -0x1

    .line 130
    .line 131
    :cond_5
    sub-long/2addr v7, v5

    .line 132
    :goto_5
    cmp-long v1, v7, p2

    .line 133
    .line 134
    if-eqz v1, :cond_6

    .line 135
    .line 136
    iget-wide v1, v0, Lu01/j;->e:J

    .line 137
    .line 138
    add-long/2addr v1, v7

    .line 139
    iput-wide v1, v0, Lu01/j;->e:J

    .line 140
    .line 141
    :cond_6
    return-wide v7

    .line 142
    :cond_7
    const-string v0, "byteCount < 0: "

    .line 143
    .line 144
    invoke-static {v2, v3, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 149
    .line 150
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw v1

    .line 158
    :cond_8
    const-string v0, "closed"

    .line 159
    .line 160
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 161
    .line 162
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    throw v1
.end method

.method public final close()V
    .locals 2

    .line 1
    iget-object v0, p0, Lu01/j;->d:Lu01/t;

    .line 2
    .line 3
    iget-boolean v1, p0, Lu01/j;->f:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v1, 0x1

    .line 9
    iput-boolean v1, p0, Lu01/j;->f:Z

    .line 10
    .line 11
    iget-object p0, v0, Lu01/t;->f:Ljava/util/concurrent/locks/ReentrantLock;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 14
    .line 15
    .line 16
    :try_start_0
    iget v1, v0, Lu01/t;->e:I

    .line 17
    .line 18
    add-int/lit8 v1, v1, -0x1

    .line 19
    .line 20
    iput v1, v0, Lu01/t;->e:I

    .line 21
    .line 22
    if-nez v1, :cond_2

    .line 23
    .line 24
    iget-boolean v1, v0, Lu01/t;->d:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 25
    .line 26
    if-nez v1, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 30
    .line 31
    .line 32
    monitor-enter v0

    .line 33
    :try_start_1
    iget-object p0, v0, Lu01/t;->g:Ljava/io/RandomAccessFile;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/io/RandomAccessFile;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    .line 37
    .line 38
    monitor-exit v0

    .line 39
    return-void

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 42
    throw p0

    .line 43
    :catchall_1
    move-exception v0

    .line 44
    goto :goto_1

    .line 45
    :cond_2
    :goto_0
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :goto_1
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 50
    .line 51
    .line 52
    throw v0
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    sget-object p0, Lu01/j0;->d:Lu01/i0;

    .line 2
    .line 3
    return-object p0
.end method

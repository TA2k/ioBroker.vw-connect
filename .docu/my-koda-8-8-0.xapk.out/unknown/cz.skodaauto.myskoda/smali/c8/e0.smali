.class public final Lc8/e0;
.super Lu7/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public i:I

.field public j:I

.field public k:Z

.field public l:I

.field public m:[B

.field public n:I

.field public o:J


# virtual methods
.method public final b()Ljava/nio/ByteBuffer;
    .locals 4

    .line 1
    invoke-super {p0}, Lu7/g;->c()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget v0, p0, Lc8/e0;->n:I

    .line 8
    .line 9
    if-lez v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lu7/g;->k(I)Ljava/nio/ByteBuffer;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lc8/e0;->m:[B

    .line 16
    .line 17
    iget v2, p0, Lc8/e0;->n:I

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-virtual {v0, v1, v3, v2}, Ljava/nio/ByteBuffer;->put([BII)Ljava/nio/ByteBuffer;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 25
    .line 26
    .line 27
    iput v3, p0, Lc8/e0;->n:I

    .line 28
    .line 29
    :cond_0
    invoke-super {p0}, Lu7/g;->b()Ljava/nio/ByteBuffer;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public final c()Z
    .locals 1

    .line 1
    invoke-super {p0}, Lu7/g;->c()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget p0, p0, Lc8/e0;->n:I

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final d(Ljava/nio/ByteBuffer;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Ljava/nio/Buffer;->position()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Ljava/nio/Buffer;->limit()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    sub-int v2, v1, v0

    .line 10
    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget v3, p0, Lc8/e0;->l:I

    .line 15
    .line 16
    invoke-static {v2, v3}, Ljava/lang/Math;->min(II)I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    iget-wide v4, p0, Lc8/e0;->o:J

    .line 21
    .line 22
    iget-object v6, p0, Lu7/g;->b:Lu7/d;

    .line 23
    .line 24
    iget v6, v6, Lu7/d;->d:I

    .line 25
    .line 26
    div-int v6, v3, v6

    .line 27
    .line 28
    int-to-long v6, v6

    .line 29
    add-long/2addr v4, v6

    .line 30
    iput-wide v4, p0, Lc8/e0;->o:J

    .line 31
    .line 32
    iget v4, p0, Lc8/e0;->l:I

    .line 33
    .line 34
    sub-int/2addr v4, v3

    .line 35
    iput v4, p0, Lc8/e0;->l:I

    .line 36
    .line 37
    add-int/2addr v0, v3

    .line 38
    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 39
    .line 40
    .line 41
    iget v0, p0, Lc8/e0;->l:I

    .line 42
    .line 43
    if-lez v0, :cond_1

    .line 44
    .line 45
    :goto_0
    return-void

    .line 46
    :cond_1
    sub-int/2addr v2, v3

    .line 47
    iget v0, p0, Lc8/e0;->n:I

    .line 48
    .line 49
    add-int/2addr v0, v2

    .line 50
    iget-object v3, p0, Lc8/e0;->m:[B

    .line 51
    .line 52
    array-length v3, v3

    .line 53
    sub-int/2addr v0, v3

    .line 54
    invoke-virtual {p0, v0}, Lu7/g;->k(I)Ljava/nio/ByteBuffer;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    iget v4, p0, Lc8/e0;->n:I

    .line 59
    .line 60
    const/4 v5, 0x0

    .line 61
    invoke-static {v0, v5, v4}, Lw7/w;->g(III)I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    iget-object v6, p0, Lc8/e0;->m:[B

    .line 66
    .line 67
    invoke-virtual {v3, v6, v5, v4}, Ljava/nio/ByteBuffer;->put([BII)Ljava/nio/ByteBuffer;

    .line 68
    .line 69
    .line 70
    sub-int/2addr v0, v4

    .line 71
    invoke-static {v0, v5, v2}, Lw7/w;->g(III)I

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    invoke-virtual {p1}, Ljava/nio/Buffer;->position()I

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    add-int/2addr v6, v0

    .line 80
    invoke-virtual {p1, v6}, Ljava/nio/ByteBuffer;->limit(I)Ljava/nio/Buffer;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v3, p1}, Ljava/nio/ByteBuffer;->put(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;

    .line 84
    .line 85
    .line 86
    invoke-virtual {p1, v1}, Ljava/nio/ByteBuffer;->limit(I)Ljava/nio/Buffer;

    .line 87
    .line 88
    .line 89
    sub-int/2addr v2, v0

    .line 90
    iget v0, p0, Lc8/e0;->n:I

    .line 91
    .line 92
    sub-int/2addr v0, v4

    .line 93
    iput v0, p0, Lc8/e0;->n:I

    .line 94
    .line 95
    iget-object v1, p0, Lc8/e0;->m:[B

    .line 96
    .line 97
    invoke-static {v1, v4, v1, v5, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 98
    .line 99
    .line 100
    iget-object v0, p0, Lc8/e0;->m:[B

    .line 101
    .line 102
    iget v1, p0, Lc8/e0;->n:I

    .line 103
    .line 104
    invoke-virtual {p1, v0, v1, v2}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 105
    .line 106
    .line 107
    iget p1, p0, Lc8/e0;->n:I

    .line 108
    .line 109
    add-int/2addr p1, v2

    .line 110
    iput p1, p0, Lc8/e0;->n:I

    .line 111
    .line 112
    invoke-virtual {v3}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 113
    .line 114
    .line 115
    return-void
.end method

.method public final g(Lu7/d;)Lu7/d;
    .locals 1

    .line 1
    iget v0, p1, Lu7/d;->c:I

    .line 2
    .line 3
    invoke-static {v0}, Lw7/w;->A(I)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    iput-boolean v0, p0, Lc8/e0;->k:Z

    .line 11
    .line 12
    iget v0, p0, Lc8/e0;->i:I

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    iget p0, p0, Lc8/e0;->j:I

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    sget-object p0, Lu7/d;->e:Lu7/d;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_1
    :goto_0
    return-object p1

    .line 25
    :cond_2
    new-instance p0, Lu7/e;

    .line 26
    .line 27
    invoke-direct {p0, p1}, Lu7/e;-><init>(Lu7/d;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public final h()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lc8/e0;->k:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lc8/e0;->k:Z

    .line 7
    .line 8
    iget v0, p0, Lc8/e0;->j:I

    .line 9
    .line 10
    iget-object v2, p0, Lu7/g;->b:Lu7/d;

    .line 11
    .line 12
    iget v2, v2, Lu7/d;->d:I

    .line 13
    .line 14
    mul-int/2addr v0, v2

    .line 15
    new-array v0, v0, [B

    .line 16
    .line 17
    iput-object v0, p0, Lc8/e0;->m:[B

    .line 18
    .line 19
    iget v0, p0, Lc8/e0;->i:I

    .line 20
    .line 21
    mul-int/2addr v0, v2

    .line 22
    iput v0, p0, Lc8/e0;->l:I

    .line 23
    .line 24
    :cond_0
    iput v1, p0, Lc8/e0;->n:I

    .line 25
    .line 26
    return-void
.end method

.method public final i()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lc8/e0;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget v0, p0, Lc8/e0;->n:I

    .line 6
    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    iget-wide v1, p0, Lc8/e0;->o:J

    .line 10
    .line 11
    iget-object v3, p0, Lu7/g;->b:Lu7/d;

    .line 12
    .line 13
    iget v3, v3, Lu7/d;->d:I

    .line 14
    .line 15
    div-int/2addr v0, v3

    .line 16
    int-to-long v3, v0

    .line 17
    add-long/2addr v1, v3

    .line 18
    iput-wide v1, p0, Lc8/e0;->o:J

    .line 19
    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    iput v0, p0, Lc8/e0;->n:I

    .line 22
    .line 23
    :cond_1
    return-void
.end method

.method public final j()V
    .locals 1

    .line 1
    sget-object v0, Lw7/w;->b:[B

    .line 2
    .line 3
    iput-object v0, p0, Lc8/e0;->m:[B

    .line 4
    .line 5
    return-void
.end method

.class public final Lu7/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu7/f;


# instance fields
.field public b:I

.field public c:F

.field public d:F

.field public e:Lu7/d;

.field public f:Lu7/d;

.field public g:Lu7/d;

.field public h:Lu7/d;

.field public i:Z

.field public j:Lu7/h;

.field public k:Ljava/nio/ByteBuffer;

.field public l:Ljava/nio/ShortBuffer;

.field public m:Ljava/nio/ByteBuffer;

.field public n:J

.field public o:J

.field public p:Z


# virtual methods
.method public final a()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lu7/i;->f:Lu7/d;

    .line 2
    .line 3
    iget v0, v0, Lu7/d;->a:I

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    if-eq v0, v1, :cond_1

    .line 7
    .line 8
    iget v0, p0, Lu7/i;->c:F

    .line 9
    .line 10
    const/high16 v1, 0x3f800000    # 1.0f

    .line 11
    .line 12
    sub-float/2addr v0, v1

    .line 13
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const v2, 0x38d1b717    # 1.0E-4f

    .line 18
    .line 19
    .line 20
    cmpg-float v0, v0, v2

    .line 21
    .line 22
    if-gez v0, :cond_0

    .line 23
    .line 24
    iget v0, p0, Lu7/i;->d:F

    .line 25
    .line 26
    sub-float/2addr v0, v1

    .line 27
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    cmpg-float v0, v0, v2

    .line 32
    .line 33
    if-gez v0, :cond_0

    .line 34
    .line 35
    iget-object v0, p0, Lu7/i;->f:Lu7/d;

    .line 36
    .line 37
    iget v0, v0, Lu7/d;->a:I

    .line 38
    .line 39
    iget-object p0, p0, Lu7/i;->e:Lu7/d;

    .line 40
    .line 41
    iget p0, p0, Lu7/d;->a:I

    .line 42
    .line 43
    if-ne v0, p0, :cond_0

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 p0, 0x1

    .line 47
    return p0

    .line 48
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 49
    return p0
.end method

.method public final b()Ljava/nio/ByteBuffer;
    .locals 8

    .line 1
    iget-object v0, p0, Lu7/i;->j:Lu7/h;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    iget v1, v0, Lu7/h;->b:I

    .line 6
    .line 7
    iget v2, v0, Lu7/h;->m:I

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x1

    .line 11
    if-ltz v2, :cond_0

    .line 12
    .line 13
    move v2, v4

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v3

    .line 16
    :goto_0
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 17
    .line 18
    .line 19
    iget v2, v0, Lu7/h;->m:I

    .line 20
    .line 21
    mul-int/2addr v2, v1

    .line 22
    mul-int/lit8 v2, v2, 0x2

    .line 23
    .line 24
    if-lez v2, :cond_3

    .line 25
    .line 26
    iget-object v5, p0, Lu7/i;->k:Ljava/nio/ByteBuffer;

    .line 27
    .line 28
    invoke-virtual {v5}, Ljava/nio/Buffer;->capacity()I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-ge v5, v2, :cond_1

    .line 33
    .line 34
    invoke-static {v2}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    invoke-static {}, Ljava/nio/ByteOrder;->nativeOrder()Ljava/nio/ByteOrder;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    invoke-virtual {v5, v6}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    iput-object v5, p0, Lu7/i;->k:Ljava/nio/ByteBuffer;

    .line 47
    .line 48
    invoke-virtual {v5}, Ljava/nio/ByteBuffer;->asShortBuffer()Ljava/nio/ShortBuffer;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    iput-object v5, p0, Lu7/i;->l:Ljava/nio/ShortBuffer;

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    iget-object v5, p0, Lu7/i;->k:Ljava/nio/ByteBuffer;

    .line 56
    .line 57
    invoke-virtual {v5}, Ljava/nio/ByteBuffer;->clear()Ljava/nio/Buffer;

    .line 58
    .line 59
    .line 60
    iget-object v5, p0, Lu7/i;->l:Ljava/nio/ShortBuffer;

    .line 61
    .line 62
    invoke-virtual {v5}, Ljava/nio/ShortBuffer;->clear()Ljava/nio/Buffer;

    .line 63
    .line 64
    .line 65
    :goto_1
    iget-object v5, p0, Lu7/i;->l:Ljava/nio/ShortBuffer;

    .line 66
    .line 67
    iget v6, v0, Lu7/h;->m:I

    .line 68
    .line 69
    if-ltz v6, :cond_2

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_2
    move v4, v3

    .line 73
    :goto_2
    invoke-static {v4}, Lw7/a;->j(Z)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v5}, Ljava/nio/Buffer;->remaining()I

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    div-int/2addr v4, v1

    .line 81
    iget v6, v0, Lu7/h;->m:I

    .line 82
    .line 83
    invoke-static {v4, v6}, Ljava/lang/Math;->min(II)I

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    iget-object v6, v0, Lu7/h;->l:[S

    .line 88
    .line 89
    mul-int v7, v4, v1

    .line 90
    .line 91
    invoke-virtual {v5, v6, v3, v7}, Ljava/nio/ShortBuffer;->put([SII)Ljava/nio/ShortBuffer;

    .line 92
    .line 93
    .line 94
    iget v5, v0, Lu7/h;->m:I

    .line 95
    .line 96
    sub-int/2addr v5, v4

    .line 97
    iput v5, v0, Lu7/h;->m:I

    .line 98
    .line 99
    iget-object v0, v0, Lu7/h;->l:[S

    .line 100
    .line 101
    mul-int/2addr v5, v1

    .line 102
    invoke-static {v0, v7, v0, v3, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 103
    .line 104
    .line 105
    iget-wide v0, p0, Lu7/i;->o:J

    .line 106
    .line 107
    int-to-long v3, v2

    .line 108
    add-long/2addr v0, v3

    .line 109
    iput-wide v0, p0, Lu7/i;->o:J

    .line 110
    .line 111
    iget-object v0, p0, Lu7/i;->k:Ljava/nio/ByteBuffer;

    .line 112
    .line 113
    invoke-virtual {v0, v2}, Ljava/nio/ByteBuffer;->limit(I)Ljava/nio/Buffer;

    .line 114
    .line 115
    .line 116
    iget-object v0, p0, Lu7/i;->k:Ljava/nio/ByteBuffer;

    .line 117
    .line 118
    iput-object v0, p0, Lu7/i;->m:Ljava/nio/ByteBuffer;

    .line 119
    .line 120
    :cond_3
    iget-object v0, p0, Lu7/i;->m:Ljava/nio/ByteBuffer;

    .line 121
    .line 122
    sget-object v1, Lu7/f;->a:Ljava/nio/ByteBuffer;

    .line 123
    .line 124
    iput-object v1, p0, Lu7/i;->m:Ljava/nio/ByteBuffer;

    .line 125
    .line 126
    return-object v0
.end method

.method public final c()Z
    .locals 3

    .line 1
    iget-boolean v0, p0, Lu7/i;->p:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_2

    .line 5
    .line 6
    iget-object p0, p0, Lu7/i;->j:Lu7/h;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    iget v2, p0, Lu7/h;->m:I

    .line 12
    .line 13
    if-ltz v2, :cond_0

    .line 14
    .line 15
    move v2, v0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v2, v1

    .line 18
    :goto_0
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 19
    .line 20
    .line 21
    iget v2, p0, Lu7/h;->m:I

    .line 22
    .line 23
    iget p0, p0, Lu7/h;->b:I

    .line 24
    .line 25
    mul-int/2addr v2, p0

    .line 26
    mul-int/lit8 v2, v2, 0x2

    .line 27
    .line 28
    if-nez v2, :cond_2

    .line 29
    .line 30
    :cond_1
    return v0

    .line 31
    :cond_2
    return v1
.end method

.method public final d(Ljava/nio/ByteBuffer;)V
    .locals 7

    .line 1
    invoke-virtual {p1}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v0, p0, Lu7/i;->j:Lu7/h;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->asShortBuffer()Ljava/nio/ShortBuffer;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    iget-wide v3, p0, Lu7/i;->n:J

    .line 22
    .line 23
    int-to-long v5, v2

    .line 24
    add-long/2addr v3, v5

    .line 25
    iput-wide v3, p0, Lu7/i;->n:J

    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/nio/Buffer;->remaining()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    iget v3, v0, Lu7/h;->b:I

    .line 32
    .line 33
    div-int/2addr p0, v3

    .line 34
    mul-int v4, p0, v3

    .line 35
    .line 36
    mul-int/lit8 v4, v4, 0x2

    .line 37
    .line 38
    iget-object v5, v0, Lu7/h;->j:[S

    .line 39
    .line 40
    iget v6, v0, Lu7/h;->k:I

    .line 41
    .line 42
    invoke-virtual {v0, v5, v6, p0}, Lu7/h;->c([SII)[S

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    iput-object v5, v0, Lu7/h;->j:[S

    .line 47
    .line 48
    iget v6, v0, Lu7/h;->k:I

    .line 49
    .line 50
    mul-int/2addr v6, v3

    .line 51
    div-int/lit8 v4, v4, 0x2

    .line 52
    .line 53
    invoke-virtual {v1, v5, v6, v4}, Ljava/nio/ShortBuffer;->get([SII)Ljava/nio/ShortBuffer;

    .line 54
    .line 55
    .line 56
    iget v1, v0, Lu7/h;->k:I

    .line 57
    .line 58
    add-int/2addr v1, p0

    .line 59
    iput v1, v0, Lu7/h;->k:I

    .line 60
    .line 61
    invoke-virtual {v0}, Lu7/h;->f()V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/nio/Buffer;->position()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    add-int/2addr p0, v2

    .line 69
    invoke-virtual {p1, p0}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final e()V
    .locals 11

    .line 1
    iget-object v0, p0, Lu7/i;->j:Lu7/h;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget v1, v0, Lu7/h;->k:I

    .line 6
    .line 7
    iget v2, v0, Lu7/h;->c:F

    .line 8
    .line 9
    iget v3, v0, Lu7/h;->d:F

    .line 10
    .line 11
    div-float/2addr v2, v3

    .line 12
    float-to-double v4, v2

    .line 13
    iget v2, v0, Lu7/h;->e:F

    .line 14
    .line 15
    mul-float/2addr v2, v3

    .line 16
    float-to-double v2, v2

    .line 17
    iget v6, v0, Lu7/h;->r:I

    .line 18
    .line 19
    sub-int v7, v1, v6

    .line 20
    .line 21
    iget v8, v0, Lu7/h;->m:I

    .line 22
    .line 23
    int-to-double v9, v7

    .line 24
    div-double/2addr v9, v4

    .line 25
    int-to-double v4, v6

    .line 26
    add-double/2addr v9, v4

    .line 27
    iget-wide v4, v0, Lu7/h;->w:D

    .line 28
    .line 29
    add-double/2addr v9, v4

    .line 30
    iget v4, v0, Lu7/h;->o:I

    .line 31
    .line 32
    int-to-double v4, v4

    .line 33
    add-double/2addr v9, v4

    .line 34
    div-double/2addr v9, v2

    .line 35
    const-wide/high16 v2, 0x3fe0000000000000L    # 0.5

    .line 36
    .line 37
    add-double/2addr v9, v2

    .line 38
    double-to-int v2, v9

    .line 39
    add-int/2addr v8, v2

    .line 40
    const-wide/16 v2, 0x0

    .line 41
    .line 42
    iput-wide v2, v0, Lu7/h;->w:D

    .line 43
    .line 44
    iget-object v2, v0, Lu7/h;->j:[S

    .line 45
    .line 46
    iget v3, v0, Lu7/h;->h:I

    .line 47
    .line 48
    mul-int/lit8 v3, v3, 0x2

    .line 49
    .line 50
    add-int v4, v3, v1

    .line 51
    .line 52
    invoke-virtual {v0, v2, v1, v4}, Lu7/h;->c([SII)[S

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    iput-object v2, v0, Lu7/h;->j:[S

    .line 57
    .line 58
    const/4 v2, 0x0

    .line 59
    move v4, v2

    .line 60
    :goto_0
    iget v5, v0, Lu7/h;->b:I

    .line 61
    .line 62
    mul-int v6, v3, v5

    .line 63
    .line 64
    if-ge v4, v6, :cond_0

    .line 65
    .line 66
    iget-object v6, v0, Lu7/h;->j:[S

    .line 67
    .line 68
    mul-int/2addr v5, v1

    .line 69
    add-int/2addr v5, v4

    .line 70
    aput-short v2, v6, v5

    .line 71
    .line 72
    add-int/lit8 v4, v4, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    iget v1, v0, Lu7/h;->k:I

    .line 76
    .line 77
    add-int/2addr v3, v1

    .line 78
    iput v3, v0, Lu7/h;->k:I

    .line 79
    .line 80
    invoke-virtual {v0}, Lu7/h;->f()V

    .line 81
    .line 82
    .line 83
    iget v1, v0, Lu7/h;->m:I

    .line 84
    .line 85
    if-le v1, v8, :cond_1

    .line 86
    .line 87
    invoke-static {v8, v2}, Ljava/lang/Math;->max(II)I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    iput v1, v0, Lu7/h;->m:I

    .line 92
    .line 93
    :cond_1
    iput v2, v0, Lu7/h;->k:I

    .line 94
    .line 95
    iput v2, v0, Lu7/h;->r:I

    .line 96
    .line 97
    iput v2, v0, Lu7/h;->o:I

    .line 98
    .line 99
    :cond_2
    const/4 v0, 0x1

    .line 100
    iput-boolean v0, p0, Lu7/i;->p:Z

    .line 101
    .line 102
    return-void
.end method

.method public final f(Lu7/d;)Lu7/d;
    .locals 3

    .line 1
    iget v0, p1, Lu7/d;->c:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    iget v0, p0, Lu7/i;->b:I

    .line 7
    .line 8
    const/4 v2, -0x1

    .line 9
    if-ne v0, v2, :cond_0

    .line 10
    .line 11
    iget v0, p1, Lu7/d;->a:I

    .line 12
    .line 13
    :cond_0
    iput-object p1, p0, Lu7/i;->e:Lu7/d;

    .line 14
    .line 15
    new-instance v2, Lu7/d;

    .line 16
    .line 17
    iget p1, p1, Lu7/d;->b:I

    .line 18
    .line 19
    invoke-direct {v2, v0, p1, v1}, Lu7/d;-><init>(III)V

    .line 20
    .line 21
    .line 22
    iput-object v2, p0, Lu7/i;->f:Lu7/d;

    .line 23
    .line 24
    const/4 p1, 0x1

    .line 25
    iput-boolean p1, p0, Lu7/i;->i:Z

    .line 26
    .line 27
    return-object v2

    .line 28
    :cond_1
    new-instance p0, Lu7/e;

    .line 29
    .line 30
    invoke-direct {p0, p1}, Lu7/e;-><init>(Lu7/d;)V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public final flush()V
    .locals 10

    .line 1
    invoke-virtual {p0}, Lu7/i;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    iget-object v0, p0, Lu7/i;->e:Lu7/d;

    .line 9
    .line 10
    iput-object v0, p0, Lu7/i;->g:Lu7/d;

    .line 11
    .line 12
    iget-object v2, p0, Lu7/i;->f:Lu7/d;

    .line 13
    .line 14
    iput-object v2, p0, Lu7/i;->h:Lu7/d;

    .line 15
    .line 16
    iget-boolean v3, p0, Lu7/i;->i:Z

    .line 17
    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    new-instance v4, Lu7/h;

    .line 21
    .line 22
    iget v5, v0, Lu7/d;->a:I

    .line 23
    .line 24
    iget v6, v0, Lu7/d;->b:I

    .line 25
    .line 26
    iget v7, p0, Lu7/i;->c:F

    .line 27
    .line 28
    iget v8, p0, Lu7/i;->d:F

    .line 29
    .line 30
    iget v9, v2, Lu7/d;->a:I

    .line 31
    .line 32
    invoke-direct/range {v4 .. v9}, Lu7/h;-><init>(IIFFI)V

    .line 33
    .line 34
    .line 35
    iput-object v4, p0, Lu7/i;->j:Lu7/h;

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    iget-object v0, p0, Lu7/i;->j:Lu7/h;

    .line 39
    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    iput v1, v0, Lu7/h;->k:I

    .line 43
    .line 44
    iput v1, v0, Lu7/h;->m:I

    .line 45
    .line 46
    iput v1, v0, Lu7/h;->o:I

    .line 47
    .line 48
    iput v1, v0, Lu7/h;->p:I

    .line 49
    .line 50
    iput v1, v0, Lu7/h;->q:I

    .line 51
    .line 52
    iput v1, v0, Lu7/h;->r:I

    .line 53
    .line 54
    iput v1, v0, Lu7/h;->s:I

    .line 55
    .line 56
    iput v1, v0, Lu7/h;->t:I

    .line 57
    .line 58
    iput v1, v0, Lu7/h;->u:I

    .line 59
    .line 60
    iput v1, v0, Lu7/h;->v:I

    .line 61
    .line 62
    const-wide/16 v2, 0x0

    .line 63
    .line 64
    iput-wide v2, v0, Lu7/h;->w:D

    .line 65
    .line 66
    :cond_1
    :goto_0
    sget-object v0, Lu7/f;->a:Ljava/nio/ByteBuffer;

    .line 67
    .line 68
    iput-object v0, p0, Lu7/i;->m:Ljava/nio/ByteBuffer;

    .line 69
    .line 70
    const-wide/16 v2, 0x0

    .line 71
    .line 72
    iput-wide v2, p0, Lu7/i;->n:J

    .line 73
    .line 74
    iput-wide v2, p0, Lu7/i;->o:J

    .line 75
    .line 76
    iput-boolean v1, p0, Lu7/i;->p:Z

    .line 77
    .line 78
    return-void
.end method

.method public final reset()V
    .locals 3

    .line 1
    const/high16 v0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    iput v0, p0, Lu7/i;->c:F

    .line 4
    .line 5
    iput v0, p0, Lu7/i;->d:F

    .line 6
    .line 7
    sget-object v0, Lu7/d;->e:Lu7/d;

    .line 8
    .line 9
    iput-object v0, p0, Lu7/i;->e:Lu7/d;

    .line 10
    .line 11
    iput-object v0, p0, Lu7/i;->f:Lu7/d;

    .line 12
    .line 13
    iput-object v0, p0, Lu7/i;->g:Lu7/d;

    .line 14
    .line 15
    iput-object v0, p0, Lu7/i;->h:Lu7/d;

    .line 16
    .line 17
    sget-object v0, Lu7/f;->a:Ljava/nio/ByteBuffer;

    .line 18
    .line 19
    iput-object v0, p0, Lu7/i;->k:Ljava/nio/ByteBuffer;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->asShortBuffer()Ljava/nio/ShortBuffer;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iput-object v1, p0, Lu7/i;->l:Ljava/nio/ShortBuffer;

    .line 26
    .line 27
    iput-object v0, p0, Lu7/i;->m:Ljava/nio/ByteBuffer;

    .line 28
    .line 29
    const/4 v0, -0x1

    .line 30
    iput v0, p0, Lu7/i;->b:I

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    iput-boolean v0, p0, Lu7/i;->i:Z

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    iput-object v1, p0, Lu7/i;->j:Lu7/h;

    .line 37
    .line 38
    const-wide/16 v1, 0x0

    .line 39
    .line 40
    iput-wide v1, p0, Lu7/i;->n:J

    .line 41
    .line 42
    iput-wide v1, p0, Lu7/i;->o:J

    .line 43
    .line 44
    iput-boolean v0, p0, Lu7/i;->p:Z

    .line 45
    .line 46
    return-void
.end method

.class public final Lh9/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh9/f;
.implements Lo8/c0;


# instance fields
.field public final a:J

.field public final b:J

.field public final c:I

.field public final d:J

.field public final e:I

.field public final f:J

.field public final g:Z

.field public final h:J

.field public final i:I

.field public final j:I

.field public final k:Z

.field public final l:J


# direct methods
.method public constructor <init>(JJIIZ)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lh9/a;->a:J

    .line 5
    .line 6
    iput-wide p3, p0, Lh9/a;->b:J

    .line 7
    .line 8
    const/4 v0, -0x1

    .line 9
    if-ne p6, v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v0, p6

    .line 14
    :goto_0
    iput v0, p0, Lh9/a;->c:I

    .line 15
    .line 16
    iput p5, p0, Lh9/a;->e:I

    .line 17
    .line 18
    iput-boolean p7, p0, Lh9/a;->g:Z

    .line 19
    .line 20
    const-wide/16 v0, -0x1

    .line 21
    .line 22
    cmp-long v2, p1, v0

    .line 23
    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    iput-wide v0, p0, Lh9/a;->d:J

    .line 27
    .line 28
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    iput-wide v0, p0, Lh9/a;->f:J

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    sub-long v0, p1, p3

    .line 37
    .line 38
    iput-wide v0, p0, Lh9/a;->d:J

    .line 39
    .line 40
    const-wide/16 v2, 0x0

    .line 41
    .line 42
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 43
    .line 44
    .line 45
    move-result-wide v0

    .line 46
    const-wide/32 v2, 0x7a1200

    .line 47
    .line 48
    .line 49
    mul-long/2addr v0, v2

    .line 50
    int-to-long v2, p5

    .line 51
    div-long/2addr v0, v2

    .line 52
    iput-wide v0, p0, Lh9/a;->f:J

    .line 53
    .line 54
    :goto_1
    iput-wide p3, p0, Lh9/a;->h:J

    .line 55
    .line 56
    iput p5, p0, Lh9/a;->i:I

    .line 57
    .line 58
    iput p6, p0, Lh9/a;->j:I

    .line 59
    .line 60
    iput-boolean p7, p0, Lh9/a;->k:Z

    .line 61
    .line 62
    const-wide/16 p3, -0x1

    .line 63
    .line 64
    cmp-long p5, p1, p3

    .line 65
    .line 66
    if-eqz p5, :cond_2

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_2
    move-wide p1, p3

    .line 70
    :goto_2
    iput-wide p1, p0, Lh9/a;->l:J

    .line 71
    .line 72
    return-void
.end method


# virtual methods
.method public final e(J)Lo8/b0;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-wide/16 v1, -0x1

    .line 4
    .line 5
    iget-wide v3, v0, Lh9/a;->d:J

    .line 6
    .line 7
    cmp-long v1, v3, v1

    .line 8
    .line 9
    iget-wide v5, v0, Lh9/a;->b:J

    .line 10
    .line 11
    const-wide/16 v7, 0x0

    .line 12
    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    iget-boolean v2, v0, Lh9/a;->g:Z

    .line 16
    .line 17
    if-nez v2, :cond_0

    .line 18
    .line 19
    new-instance v0, Lo8/b0;

    .line 20
    .line 21
    new-instance v1, Lo8/d0;

    .line 22
    .line 23
    invoke-direct {v1, v7, v8, v5, v6}, Lo8/d0;-><init>(JJ)V

    .line 24
    .line 25
    .line 26
    invoke-direct {v0, v1, v1}, Lo8/b0;-><init>(Lo8/d0;Lo8/d0;)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    :cond_0
    iget v2, v0, Lh9/a;->e:I

    .line 31
    .line 32
    int-to-long v9, v2

    .line 33
    mul-long v9, v9, p1

    .line 34
    .line 35
    const-wide/32 v11, 0x7a1200

    .line 36
    .line 37
    .line 38
    div-long/2addr v9, v11

    .line 39
    iget v13, v0, Lh9/a;->c:I

    .line 40
    .line 41
    int-to-long v13, v13

    .line 42
    div-long/2addr v9, v13

    .line 43
    mul-long/2addr v9, v13

    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    sub-long/2addr v3, v13

    .line 47
    invoke-static {v9, v10, v3, v4}, Ljava/lang/Math;->min(JJ)J

    .line 48
    .line 49
    .line 50
    move-result-wide v9

    .line 51
    :cond_1
    invoke-static {v9, v10, v7, v8}, Ljava/lang/Math;->max(JJ)J

    .line 52
    .line 53
    .line 54
    move-result-wide v3

    .line 55
    add-long/2addr v3, v5

    .line 56
    sub-long v9, v3, v5

    .line 57
    .line 58
    invoke-static {v7, v8, v9, v10}, Ljava/lang/Math;->max(JJ)J

    .line 59
    .line 60
    .line 61
    move-result-wide v9

    .line 62
    mul-long/2addr v9, v11

    .line 63
    move-wide v15, v11

    .line 64
    int-to-long v11, v2

    .line 65
    div-long/2addr v9, v11

    .line 66
    new-instance v11, Lo8/d0;

    .line 67
    .line 68
    invoke-direct {v11, v9, v10, v3, v4}, Lo8/d0;-><init>(JJ)V

    .line 69
    .line 70
    .line 71
    if-eqz v1, :cond_3

    .line 72
    .line 73
    cmp-long v1, v9, p1

    .line 74
    .line 75
    if-gez v1, :cond_3

    .line 76
    .line 77
    add-long/2addr v3, v13

    .line 78
    iget-wide v0, v0, Lh9/a;->a:J

    .line 79
    .line 80
    cmp-long v0, v3, v0

    .line 81
    .line 82
    if-ltz v0, :cond_2

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_2
    sub-long v0, v3, v5

    .line 86
    .line 87
    invoke-static {v7, v8, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 88
    .line 89
    .line 90
    move-result-wide v0

    .line 91
    mul-long/2addr v0, v15

    .line 92
    int-to-long v5, v2

    .line 93
    div-long/2addr v0, v5

    .line 94
    new-instance v2, Lo8/d0;

    .line 95
    .line 96
    invoke-direct {v2, v0, v1, v3, v4}, Lo8/d0;-><init>(JJ)V

    .line 97
    .line 98
    .line 99
    new-instance v0, Lo8/b0;

    .line 100
    .line 101
    invoke-direct {v0, v11, v2}, Lo8/b0;-><init>(Lo8/d0;Lo8/d0;)V

    .line 102
    .line 103
    .line 104
    return-object v0

    .line 105
    :cond_3
    :goto_0
    new-instance v0, Lo8/b0;

    .line 106
    .line 107
    invoke-direct {v0, v11, v11}, Lo8/b0;-><init>(Lo8/d0;Lo8/d0;)V

    .line 108
    .line 109
    .line 110
    return-object v0
.end method

.method public final f()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lh9/a;->l:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final g()Z
    .locals 4

    .line 1
    iget-wide v0, p0, Lh9/a;->d:J

    .line 2
    .line 3
    const-wide/16 v2, -0x1

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean p0, p0, Lh9/a;->g:Z

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public final i(J)J
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iget-wide v2, p0, Lh9/a;->b:J

    .line 4
    .line 5
    sub-long/2addr p1, v2

    .line 6
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->max(JJ)J

    .line 7
    .line 8
    .line 9
    move-result-wide p1

    .line 10
    const-wide/32 v0, 0x7a1200

    .line 11
    .line 12
    .line 13
    mul-long/2addr p1, v0

    .line 14
    iget p0, p0, Lh9/a;->e:I

    .line 15
    .line 16
    int-to-long v0, p0

    .line 17
    div-long/2addr p1, v0

    .line 18
    return-wide p1
.end method

.method public final k()I
    .locals 0

    .line 1
    iget p0, p0, Lh9/a;->i:I

    .line 2
    .line 3
    return p0
.end method

.method public final l()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lh9/a;->f:J

    .line 2
    .line 3
    return-wide v0
.end method

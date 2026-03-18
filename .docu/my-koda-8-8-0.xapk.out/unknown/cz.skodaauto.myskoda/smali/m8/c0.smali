.class public final Lm8/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lm8/e;

.field public final b:Lm8/a0;

.field public final c:Lm8/b0;

.field public d:Z

.field public e:Landroid/view/Surface;

.field public f:F

.field public g:F

.field public h:F

.field public i:F

.field public j:I

.field public k:J

.field public l:J

.field public m:J

.field public n:J

.field public o:J

.field public p:J

.field public q:J


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lm8/e;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lm8/d;

    .line 10
    .line 11
    invoke-direct {v1}, Lm8/d;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object v1, v0, Lm8/e;->a:Lm8/d;

    .line 15
    .line 16
    new-instance v1, Lm8/d;

    .line 17
    .line 18
    invoke-direct {v1}, Lm8/d;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object v1, v0, Lm8/e;->b:Lm8/d;

    .line 22
    .line 23
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    iput-wide v1, v0, Lm8/e;->d:J

    .line 29
    .line 30
    iput-object v0, p0, Lm8/c0;->a:Lm8/e;

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    if-nez p1, :cond_1

    .line 34
    .line 35
    :cond_0
    move-object v3, v0

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const-string v3, "display"

    .line 38
    .line 39
    invoke-virtual {p1, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, Landroid/hardware/display/DisplayManager;

    .line 44
    .line 45
    if-eqz p1, :cond_0

    .line 46
    .line 47
    new-instance v3, Lm8/a0;

    .line 48
    .line 49
    invoke-direct {v3, p0, p1}, Lm8/a0;-><init>(Lm8/c0;Landroid/hardware/display/DisplayManager;)V

    .line 50
    .line 51
    .line 52
    :goto_0
    iput-object v3, p0, Lm8/c0;->b:Lm8/a0;

    .line 53
    .line 54
    if-eqz v3, :cond_2

    .line 55
    .line 56
    sget-object v0, Lm8/b0;->h:Lm8/b0;

    .line 57
    .line 58
    :cond_2
    iput-object v0, p0, Lm8/c0;->c:Lm8/b0;

    .line 59
    .line 60
    iput-wide v1, p0, Lm8/c0;->k:J

    .line 61
    .line 62
    iput-wide v1, p0, Lm8/c0;->l:J

    .line 63
    .line 64
    const/high16 p1, -0x40800000    # -1.0f

    .line 65
    .line 66
    iput p1, p0, Lm8/c0;->f:F

    .line 67
    .line 68
    const/high16 p1, 0x3f800000    # 1.0f

    .line 69
    .line 70
    iput p1, p0, Lm8/c0;->i:F

    .line 71
    .line 72
    const/4 p1, 0x0

    .line 73
    iput p1, p0, Lm8/c0;->j:I

    .line 74
    .line 75
    return-void
.end method

.method public static a(Lm8/c0;Landroid/view/Display;)V
    .locals 4

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/Display;->getRefreshRate()F

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    float-to-double v0, p1

    .line 8
    const-wide v2, 0x41cdcd6500000000L    # 1.0E9

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    div-double/2addr v2, v0

    .line 14
    double-to-long v0, v2

    .line 15
    iput-wide v0, p0, Lm8/c0;->k:J

    .line 16
    .line 17
    const-wide/16 v2, 0x50

    .line 18
    .line 19
    mul-long/2addr v0, v2

    .line 20
    const-wide/16 v2, 0x64

    .line 21
    .line 22
    div-long/2addr v0, v2

    .line 23
    iput-wide v0, p0, Lm8/c0;->l:J

    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    const-string p1, "VideoFrameReleaseHelper"

    .line 27
    .line 28
    const-string v0, "Unable to query display refresh rate"

    .line 29
    .line 30
    invoke-static {p1, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    iput-wide v0, p0, Lm8/c0;->k:J

    .line 39
    .line 40
    iput-wide v0, p0, Lm8/c0;->l:J

    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 3

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1e

    .line 4
    .line 5
    if-lt v0, v1, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Lm8/c0;->e:Landroid/view/Surface;

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget v1, p0, Lm8/c0;->j:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    if-eq v1, v2, :cond_1

    .line 16
    .line 17
    iget v1, p0, Lm8/c0;->h:F

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    cmpl-float v1, v1, v2

    .line 21
    .line 22
    if-nez v1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iput v2, p0, Lm8/c0;->h:F

    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    :try_start_0
    invoke-static {v0, v2, p0}, Ld6/t1;->l(Landroid/view/Surface;FI)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :catch_0
    move-exception p0

    .line 33
    const-string v0, "VideoFrameReleaseHelper"

    .line 34
    .line 35
    const-string v1, "Failed to call Surface.setFrameRate"

    .line 36
    .line 37
    invoke-static {v0, v1, p0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    :goto_0
    return-void
.end method

.method public final c()V
    .locals 9

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1e

    .line 4
    .line 5
    if-lt v0, v1, :cond_9

    .line 6
    .line 7
    iget-object v0, p0, Lm8/c0;->e:Landroid/view/Surface;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto/16 :goto_5

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lm8/c0;->a:Lm8/e;

    .line 14
    .line 15
    iget-object v2, v0, Lm8/e;->a:Lm8/d;

    .line 16
    .line 17
    invoke-virtual {v2}, Lm8/d;->a()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/high16 v3, -0x40800000    # -1.0f

    .line 22
    .line 23
    if-eqz v2, :cond_3

    .line 24
    .line 25
    iget-object v2, v0, Lm8/e;->a:Lm8/d;

    .line 26
    .line 27
    invoke-virtual {v2}, Lm8/d;->a()Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    iget-object v2, v0, Lm8/e;->a:Lm8/d;

    .line 34
    .line 35
    iget-wide v4, v2, Lm8/d;->e:J

    .line 36
    .line 37
    const-wide/16 v6, 0x0

    .line 38
    .line 39
    cmp-long v8, v4, v6

    .line 40
    .line 41
    if-nez v8, :cond_1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    iget-wide v6, v2, Lm8/d;->f:J

    .line 45
    .line 46
    div-long/2addr v6, v4

    .line 47
    :goto_0
    long-to-double v4, v6

    .line 48
    const-wide v6, 0x41cdcd6500000000L    # 1.0E9

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    div-double/2addr v6, v4

    .line 54
    double-to-float v2, v6

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    move v2, v3

    .line 57
    goto :goto_1

    .line 58
    :cond_3
    iget v2, p0, Lm8/c0;->f:F

    .line 59
    .line 60
    :goto_1
    iget v4, p0, Lm8/c0;->g:F

    .line 61
    .line 62
    cmpl-float v5, v2, v4

    .line 63
    .line 64
    if-nez v5, :cond_4

    .line 65
    .line 66
    goto :goto_5

    .line 67
    :cond_4
    cmpl-float v5, v2, v3

    .line 68
    .line 69
    if-eqz v5, :cond_7

    .line 70
    .line 71
    cmpl-float v3, v4, v3

    .line 72
    .line 73
    if-eqz v3, :cond_7

    .line 74
    .line 75
    iget-object v1, v0, Lm8/e;->a:Lm8/d;

    .line 76
    .line 77
    invoke-virtual {v1}, Lm8/d;->a()Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eqz v1, :cond_6

    .line 82
    .line 83
    iget-object v1, v0, Lm8/e;->a:Lm8/d;

    .line 84
    .line 85
    invoke-virtual {v1}, Lm8/d;->a()Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    if-eqz v1, :cond_5

    .line 90
    .line 91
    iget-object v0, v0, Lm8/e;->a:Lm8/d;

    .line 92
    .line 93
    iget-wide v0, v0, Lm8/d;->f:J

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_5
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 97
    .line 98
    .line 99
    .line 100
    .line 101
    :goto_2
    const-wide v3, 0x12a05f200L

    .line 102
    .line 103
    .line 104
    .line 105
    .line 106
    cmp-long v0, v0, v3

    .line 107
    .line 108
    if-ltz v0, :cond_6

    .line 109
    .line 110
    const v0, 0x3ca3d70a    # 0.02f

    .line 111
    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_6
    const/high16 v0, 0x3f800000    # 1.0f

    .line 115
    .line 116
    :goto_3
    iget v1, p0, Lm8/c0;->g:F

    .line 117
    .line 118
    sub-float v1, v2, v1

    .line 119
    .line 120
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    cmpl-float v0, v1, v0

    .line 125
    .line 126
    if-ltz v0, :cond_9

    .line 127
    .line 128
    goto :goto_4

    .line 129
    :cond_7
    if-eqz v5, :cond_8

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_8
    iget v0, v0, Lm8/e;->e:I

    .line 133
    .line 134
    if-lt v0, v1, :cond_9

    .line 135
    .line 136
    :goto_4
    iput v2, p0, Lm8/c0;->g:F

    .line 137
    .line 138
    const/4 v0, 0x0

    .line 139
    invoke-virtual {p0, v0}, Lm8/c0;->d(Z)V

    .line 140
    .line 141
    .line 142
    :cond_9
    :goto_5
    return-void
.end method

.method public final d(Z)V
    .locals 4

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1e

    .line 4
    .line 5
    if-lt v0, v1, :cond_4

    .line 6
    .line 7
    iget-object v0, p0, Lm8/c0;->e:Landroid/view/Surface;

    .line 8
    .line 9
    if-eqz v0, :cond_4

    .line 10
    .line 11
    iget v1, p0, Lm8/c0;->j:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

    .line 16
    .line 17
    goto :goto_2

    .line 18
    :cond_0
    iget-boolean v1, p0, Lm8/c0;->d:Z

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    iget v1, p0, Lm8/c0;->g:F

    .line 24
    .line 25
    const/high16 v3, -0x40800000    # -1.0f

    .line 26
    .line 27
    cmpl-float v3, v1, v3

    .line 28
    .line 29
    if-eqz v3, :cond_1

    .line 30
    .line 31
    iget v3, p0, Lm8/c0;->i:F

    .line 32
    .line 33
    mul-float/2addr v1, v3

    .line 34
    goto :goto_0

    .line 35
    :cond_1
    move v1, v2

    .line 36
    :goto_0
    if-nez p1, :cond_2

    .line 37
    .line 38
    iget p1, p0, Lm8/c0;->h:F

    .line 39
    .line 40
    cmpl-float p1, p1, v1

    .line 41
    .line 42
    if-nez p1, :cond_2

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    iput v1, p0, Lm8/c0;->h:F

    .line 46
    .line 47
    cmpl-float p0, v1, v2

    .line 48
    .line 49
    if-nez p0, :cond_3

    .line 50
    .line 51
    const/4 p0, 0x0

    .line 52
    goto :goto_1

    .line 53
    :cond_3
    const/4 p0, 0x1

    .line 54
    :goto_1
    :try_start_0
    invoke-static {v0, v1, p0}, Ld6/t1;->l(Landroid/view/Surface;FI)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :catch_0
    move-exception p0

    .line 59
    const-string p1, "VideoFrameReleaseHelper"

    .line 60
    .line 61
    const-string v0, "Failed to call Surface.setFrameRate"

    .line 62
    .line 63
    invoke-static {p1, v0, p0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    :cond_4
    :goto_2
    return-void
.end method

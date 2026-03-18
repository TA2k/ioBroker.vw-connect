.class public final Ln8/l;
.super Landroid/view/GestureDetector$SimpleOnGestureListener;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnTouchListener;
.implements Ln8/c;


# instance fields
.field public final d:Landroid/graphics/PointF;

.field public final e:Landroid/graphics/PointF;

.field public final f:Ln8/j;

.field public final g:F

.field public final h:Landroid/view/GestureDetector;

.field public volatile i:F


# direct methods
.method public constructor <init>(Landroid/content/Context;Ln8/j;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroid/view/GestureDetector$SimpleOnGestureListener;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/PointF;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/PointF;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ln8/l;->d:Landroid/graphics/PointF;

    .line 10
    .line 11
    new-instance v0, Landroid/graphics/PointF;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/graphics/PointF;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ln8/l;->e:Landroid/graphics/PointF;

    .line 17
    .line 18
    iput-object p2, p0, Ln8/l;->f:Ln8/j;

    .line 19
    .line 20
    const/high16 p2, 0x41c80000    # 25.0f

    .line 21
    .line 22
    iput p2, p0, Ln8/l;->g:F

    .line 23
    .line 24
    new-instance p2, Landroid/view/GestureDetector;

    .line 25
    .line 26
    invoke-direct {p2, p1, p0}, Landroid/view/GestureDetector;-><init>(Landroid/content/Context;Landroid/view/GestureDetector$OnGestureListener;)V

    .line 27
    .line 28
    .line 29
    iput-object p2, p0, Ln8/l;->h:Landroid/view/GestureDetector;

    .line 30
    .line 31
    const p1, 0x40490fdb    # (float)Math.PI

    .line 32
    .line 33
    .line 34
    iput p1, p0, Ln8/l;->i:F

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final a(F[F)V
    .locals 0

    .line 1
    neg-float p1, p1

    .line 2
    iput p1, p0, Ln8/l;->i:F

    .line 3
    .line 4
    return-void
.end method

.method public final onDown(Landroid/view/MotionEvent;)Z
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    iget-object p0, p0, Ln8/l;->d:Landroid/graphics/PointF;

    .line 10
    .line 11
    invoke-virtual {p0, v0, p1}, Landroid/graphics/PointF;->set(FF)V

    .line 12
    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public final onScroll(Landroid/view/MotionEvent;Landroid/view/MotionEvent;FF)Z
    .locals 14

    .line 1
    invoke-virtual/range {p2 .. p2}, Landroid/view/MotionEvent;->getX()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Ln8/l;->d:Landroid/graphics/PointF;

    .line 6
    .line 7
    iget v1, v1, Landroid/graphics/PointF;->x:F

    .line 8
    .line 9
    sub-float/2addr v0, v1

    .line 10
    iget v1, p0, Ln8/l;->g:F

    .line 11
    .line 12
    div-float/2addr v0, v1

    .line 13
    invoke-virtual/range {p2 .. p2}, Landroid/view/MotionEvent;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    iget-object v2, p0, Ln8/l;->d:Landroid/graphics/PointF;

    .line 18
    .line 19
    iget v3, v2, Landroid/graphics/PointF;->y:F

    .line 20
    .line 21
    sub-float/2addr v1, v3

    .line 22
    iget v3, p0, Ln8/l;->g:F

    .line 23
    .line 24
    div-float/2addr v1, v3

    .line 25
    invoke-virtual/range {p2 .. p2}, Landroid/view/MotionEvent;->getX()F

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    invoke-virtual/range {p2 .. p2}, Landroid/view/MotionEvent;->getY()F

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    invoke-virtual {v2, v3, v4}, Landroid/graphics/PointF;->set(FF)V

    .line 34
    .line 35
    .line 36
    iget v2, p0, Ln8/l;->i:F

    .line 37
    .line 38
    float-to-double v2, v2

    .line 39
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    .line 40
    .line 41
    .line 42
    move-result-wide v4

    .line 43
    double-to-float v4, v4

    .line 44
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 45
    .line 46
    .line 47
    move-result-wide v2

    .line 48
    double-to-float v2, v2

    .line 49
    iget-object v3, p0, Ln8/l;->e:Landroid/graphics/PointF;

    .line 50
    .line 51
    iget v5, v3, Landroid/graphics/PointF;->x:F

    .line 52
    .line 53
    mul-float v6, v4, v0

    .line 54
    .line 55
    mul-float v7, v2, v1

    .line 56
    .line 57
    sub-float/2addr v6, v7

    .line 58
    sub-float/2addr v5, v6

    .line 59
    iput v5, v3, Landroid/graphics/PointF;->x:F

    .line 60
    .line 61
    iget v5, v3, Landroid/graphics/PointF;->y:F

    .line 62
    .line 63
    mul-float/2addr v2, v0

    .line 64
    mul-float/2addr v4, v1

    .line 65
    add-float/2addr v4, v2

    .line 66
    add-float/2addr v4, v5

    .line 67
    iput v4, v3, Landroid/graphics/PointF;->y:F

    .line 68
    .line 69
    const/high16 v0, 0x42340000    # 45.0f

    .line 70
    .line 71
    invoke-static {v0, v4}, Ljava/lang/Math;->min(FF)F

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    const/high16 v1, -0x3dcc0000    # -45.0f

    .line 76
    .line 77
    invoke-static {v1, v0}, Ljava/lang/Math;->max(FF)F

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    iput v0, v3, Landroid/graphics/PointF;->y:F

    .line 82
    .line 83
    iget-object v1, p0, Ln8/l;->f:Ln8/j;

    .line 84
    .line 85
    iget-object p0, p0, Ln8/l;->e:Landroid/graphics/PointF;

    .line 86
    .line 87
    monitor-enter v1

    .line 88
    :try_start_0
    iget v0, p0, Landroid/graphics/PointF;->y:F

    .line 89
    .line 90
    iput v0, v1, Ln8/j;->j:F

    .line 91
    .line 92
    iget-object v2, v1, Ln8/j;->h:[F

    .line 93
    .line 94
    neg-float v4, v0

    .line 95
    iget v0, v1, Ln8/j;->k:F

    .line 96
    .line 97
    float-to-double v5, v0

    .line 98
    invoke-static {v5, v6}, Ljava/lang/Math;->cos(D)D

    .line 99
    .line 100
    .line 101
    move-result-wide v5

    .line 102
    double-to-float v5, v5

    .line 103
    iget v0, v1, Ln8/j;->k:F

    .line 104
    .line 105
    float-to-double v6, v0

    .line 106
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 107
    .line 108
    .line 109
    move-result-wide v6

    .line 110
    double-to-float v6, v6

    .line 111
    const/4 v7, 0x0

    .line 112
    const/4 v3, 0x0

    .line 113
    invoke-static/range {v2 .. v7}, Landroid/opengl/Matrix;->setRotateM([FIFFFF)V

    .line 114
    .line 115
    .line 116
    iget-object v8, v1, Ln8/j;->i:[F

    .line 117
    .line 118
    iget p0, p0, Landroid/graphics/PointF;->x:F

    .line 119
    .line 120
    neg-float v10, p0

    .line 121
    const/high16 v12, 0x3f800000    # 1.0f

    .line 122
    .line 123
    const/4 v13, 0x0

    .line 124
    const/4 v9, 0x0

    .line 125
    const/4 v11, 0x0

    .line 126
    invoke-static/range {v8 .. v13}, Landroid/opengl/Matrix;->setRotateM([FIFFFF)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 127
    .line 128
    .line 129
    monitor-exit v1

    .line 130
    const/4 p0, 0x1

    .line 131
    return p0

    .line 132
    :catchall_0
    move-exception v0

    .line 133
    move-object p0, v0

    .line 134
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 135
    throw p0
.end method

.method public final onSingleTapUp(Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ln8/l;->f:Ln8/j;

    .line 2
    .line 3
    iget-object p0, p0, Ln8/j;->n:Ln8/k;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/view/View;->performClick()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final onTouch(Landroid/view/View;Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ln8/l;->h:Landroid/view/GestureDetector;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Landroid/view/GestureDetector;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

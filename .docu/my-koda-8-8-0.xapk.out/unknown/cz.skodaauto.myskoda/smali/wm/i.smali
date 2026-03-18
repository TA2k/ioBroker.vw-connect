.class public final Lwm/i;
.super Lwm/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final p:Z

.field public final q:Landroidx/collection/u;

.field public final r:Landroidx/collection/u;

.field public final s:Landroid/graphics/RectF;

.field public final t:I

.field public final u:I

.field public final v:Lxm/h;

.field public final w:Lxm/h;

.field public final x:Lxm/h;


# direct methods
.method public constructor <init>(Lum/j;Ldn/b;Lcn/e;)V
    .locals 11

    .line 1
    iget v0, p3, Lcn/e;->g:I

    .line 2
    .line 3
    invoke-static {v0}, Lu/w;->o(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    sget-object v0, Landroid/graphics/Paint$Cap;->SQUARE:Landroid/graphics/Paint$Cap;

    .line 13
    .line 14
    :goto_0
    move-object v3, v0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    sget-object v0, Landroid/graphics/Paint$Cap;->ROUND:Landroid/graphics/Paint$Cap;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    sget-object v0, Landroid/graphics/Paint$Cap;->BUTT:Landroid/graphics/Paint$Cap;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :goto_1
    iget v0, p3, Lcn/e;->h:I

    .line 23
    .line 24
    invoke-static {v0}, Lu/w;->o(I)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v10, 0x0

    .line 29
    if-eqz v0, :cond_4

    .line 30
    .line 31
    if-eq v0, v1, :cond_3

    .line 32
    .line 33
    const/4 v1, 0x2

    .line 34
    if-eq v0, v1, :cond_2

    .line 35
    .line 36
    move-object v4, v10

    .line 37
    goto :goto_3

    .line 38
    :cond_2
    sget-object v0, Landroid/graphics/Paint$Join;->BEVEL:Landroid/graphics/Paint$Join;

    .line 39
    .line 40
    :goto_2
    move-object v4, v0

    .line 41
    goto :goto_3

    .line 42
    :cond_3
    sget-object v0, Landroid/graphics/Paint$Join;->ROUND:Landroid/graphics/Paint$Join;

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_4
    sget-object v0, Landroid/graphics/Paint$Join;->MITER:Landroid/graphics/Paint$Join;

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :goto_3
    iget v5, p3, Lcn/e;->i:F

    .line 49
    .line 50
    iget-object v6, p3, Lcn/e;->c:Lbn/a;

    .line 51
    .line 52
    iget-object v7, p3, Lcn/e;->f:Lbn/b;

    .line 53
    .line 54
    iget-object v8, p3, Lcn/e;->j:Ljava/util/ArrayList;

    .line 55
    .line 56
    iget-object v9, p3, Lcn/e;->k:Lbn/b;

    .line 57
    .line 58
    move-object v0, p0

    .line 59
    move-object v1, p1

    .line 60
    move-object v2, p2

    .line 61
    invoke-direct/range {v0 .. v9}, Lwm/b;-><init>(Lum/j;Ldn/b;Landroid/graphics/Paint$Cap;Landroid/graphics/Paint$Join;FLbn/a;Lbn/b;Ljava/util/ArrayList;Lbn/b;)V

    .line 62
    .line 63
    .line 64
    new-instance v1, Landroidx/collection/u;

    .line 65
    .line 66
    invoke-direct {v1, v10}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput-object v1, p0, Lwm/i;->q:Landroidx/collection/u;

    .line 70
    .line 71
    new-instance v1, Landroidx/collection/u;

    .line 72
    .line 73
    invoke-direct {v1, v10}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iput-object v1, p0, Lwm/i;->r:Landroidx/collection/u;

    .line 77
    .line 78
    new-instance v1, Landroid/graphics/RectF;

    .line 79
    .line 80
    invoke-direct {v1}, Landroid/graphics/RectF;-><init>()V

    .line 81
    .line 82
    .line 83
    iput-object v1, p0, Lwm/i;->s:Landroid/graphics/RectF;

    .line 84
    .line 85
    iget v1, p3, Lcn/e;->a:I

    .line 86
    .line 87
    iput v1, p0, Lwm/i;->t:I

    .line 88
    .line 89
    iget-boolean v1, p3, Lcn/e;->l:Z

    .line 90
    .line 91
    iput-boolean v1, p0, Lwm/i;->p:Z

    .line 92
    .line 93
    iget-object v1, p1, Lum/j;->d:Lum/a;

    .line 94
    .line 95
    invoke-virtual {v1}, Lum/a;->b()F

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    const/high16 v3, 0x42000000    # 32.0f

    .line 100
    .line 101
    div-float/2addr v1, v3

    .line 102
    float-to-int v1, v1

    .line 103
    iput v1, p0, Lwm/i;->u:I

    .line 104
    .line 105
    iget-object v1, p3, Lcn/e;->b:Lbn/a;

    .line 106
    .line 107
    invoke-virtual {v1}, Lbn/a;->p()Lxm/e;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    move-object v3, v1

    .line 112
    check-cast v3, Lxm/h;

    .line 113
    .line 114
    iput-object v3, p0, Lwm/i;->v:Lxm/h;

    .line 115
    .line 116
    invoke-virtual {v1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p2, v1}, Ldn/b;->f(Lxm/e;)V

    .line 120
    .line 121
    .line 122
    iget-object v1, p3, Lcn/e;->d:Lbn/a;

    .line 123
    .line 124
    invoke-virtual {v1}, Lbn/a;->p()Lxm/e;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    move-object v3, v1

    .line 129
    check-cast v3, Lxm/h;

    .line 130
    .line 131
    iput-object v3, p0, Lwm/i;->w:Lxm/h;

    .line 132
    .line 133
    invoke-virtual {v1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p2, v1}, Ldn/b;->f(Lxm/e;)V

    .line 137
    .line 138
    .line 139
    iget-object v1, p3, Lcn/e;->e:Lbn/a;

    .line 140
    .line 141
    invoke-virtual {v1}, Lbn/a;->p()Lxm/e;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    move-object v3, v1

    .line 146
    check-cast v3, Lxm/h;

    .line 147
    .line 148
    iput-object v3, p0, Lwm/i;->x:Lxm/h;

    .line 149
    .line 150
    invoke-virtual {v1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p2, v1}, Ldn/b;->f(Lxm/e;)V

    .line 154
    .line 155
    .line 156
    return-void
.end method


# virtual methods
.method public final c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Lwm/i;->p:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v1, v0, Lwm/i;->s:Landroid/graphics/RectF;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    move-object/from16 v3, p2

    .line 12
    .line 13
    invoke-virtual {v0, v1, v3, v2}, Lwm/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 14
    .line 15
    .line 16
    iget v1, v0, Lwm/i;->t:I

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    iget-object v4, v0, Lwm/i;->v:Lxm/h;

    .line 20
    .line 21
    iget-object v5, v0, Lwm/i;->x:Lxm/h;

    .line 22
    .line 23
    iget-object v6, v0, Lwm/i;->w:Lxm/h;

    .line 24
    .line 25
    if-ne v1, v2, :cond_2

    .line 26
    .line 27
    invoke-virtual {v0}, Lwm/i;->f()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    int-to-long v1, v1

    .line 32
    iget-object v7, v0, Lwm/i;->q:Landroidx/collection/u;

    .line 33
    .line 34
    invoke-virtual {v7, v1, v2}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v8

    .line 38
    check-cast v8, Landroid/graphics/LinearGradient;

    .line 39
    .line 40
    if-eqz v8, :cond_1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    invoke-virtual {v6}, Lxm/e;->d()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    check-cast v6, Landroid/graphics/PointF;

    .line 48
    .line 49
    invoke-virtual {v5}, Lxm/e;->d()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    check-cast v5, Landroid/graphics/PointF;

    .line 54
    .line 55
    invoke-virtual {v4}, Lxm/e;->d()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    check-cast v4, Lcn/c;

    .line 60
    .line 61
    iget-object v13, v4, Lcn/c;->b:[I

    .line 62
    .line 63
    iget-object v14, v4, Lcn/c;->a:[F

    .line 64
    .line 65
    iget v9, v6, Landroid/graphics/PointF;->x:F

    .line 66
    .line 67
    iget v10, v6, Landroid/graphics/PointF;->y:F

    .line 68
    .line 69
    iget v11, v5, Landroid/graphics/PointF;->x:F

    .line 70
    .line 71
    iget v12, v5, Landroid/graphics/PointF;->y:F

    .line 72
    .line 73
    new-instance v8, Landroid/graphics/LinearGradient;

    .line 74
    .line 75
    sget-object v15, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 76
    .line 77
    invoke-direct/range {v8 .. v15}, Landroid/graphics/LinearGradient;-><init>(FFFF[I[FLandroid/graphics/Shader$TileMode;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v7, v1, v2, v8}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_2
    invoke-virtual {v0}, Lwm/i;->f()I

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    int-to-long v1, v1

    .line 89
    iget-object v7, v0, Lwm/i;->r:Landroidx/collection/u;

    .line 90
    .line 91
    invoke-virtual {v7, v1, v2}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    check-cast v8, Landroid/graphics/RadialGradient;

    .line 96
    .line 97
    if-eqz v8, :cond_3

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_3
    invoke-virtual {v6}, Lxm/e;->d()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    check-cast v6, Landroid/graphics/PointF;

    .line 105
    .line 106
    invoke-virtual {v5}, Lxm/e;->d()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v5

    .line 110
    check-cast v5, Landroid/graphics/PointF;

    .line 111
    .line 112
    invoke-virtual {v4}, Lxm/e;->d()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    check-cast v4, Lcn/c;

    .line 117
    .line 118
    iget-object v12, v4, Lcn/c;->b:[I

    .line 119
    .line 120
    iget-object v13, v4, Lcn/c;->a:[F

    .line 121
    .line 122
    iget v9, v6, Landroid/graphics/PointF;->x:F

    .line 123
    .line 124
    iget v10, v6, Landroid/graphics/PointF;->y:F

    .line 125
    .line 126
    iget v4, v5, Landroid/graphics/PointF;->x:F

    .line 127
    .line 128
    iget v5, v5, Landroid/graphics/PointF;->y:F

    .line 129
    .line 130
    sub-float/2addr v4, v9

    .line 131
    float-to-double v14, v4

    .line 132
    sub-float/2addr v5, v10

    .line 133
    float-to-double v4, v5

    .line 134
    invoke-static {v14, v15, v4, v5}, Ljava/lang/Math;->hypot(DD)D

    .line 135
    .line 136
    .line 137
    move-result-wide v4

    .line 138
    double-to-float v11, v4

    .line 139
    new-instance v8, Landroid/graphics/RadialGradient;

    .line 140
    .line 141
    sget-object v14, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 142
    .line 143
    invoke-direct/range {v8 .. v14}, Landroid/graphics/RadialGradient;-><init>(FFF[I[FLandroid/graphics/Shader$TileMode;)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v7, v1, v2, v8}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :goto_0
    iget-object v1, v0, Lwm/b;->i:Ldn/i;

    .line 150
    .line 151
    invoke-virtual {v1, v8}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 152
    .line 153
    .line 154
    invoke-super/range {p0 .. p4}, Lwm/b;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 155
    .line 156
    .line 157
    return-void
.end method

.method public final f()I
    .locals 3

    .line 1
    iget-object v0, p0, Lwm/i;->w:Lxm/h;

    .line 2
    .line 3
    iget v0, v0, Lxm/e;->d:F

    .line 4
    .line 5
    iget v1, p0, Lwm/i;->u:I

    .line 6
    .line 7
    int-to-float v1, v1

    .line 8
    mul-float/2addr v0, v1

    .line 9
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget-object v2, p0, Lwm/i;->x:Lxm/h;

    .line 14
    .line 15
    iget v2, v2, Lxm/e;->d:F

    .line 16
    .line 17
    mul-float/2addr v2, v1

    .line 18
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    iget-object p0, p0, Lwm/i;->v:Lxm/h;

    .line 23
    .line 24
    iget p0, p0, Lxm/e;->d:F

    .line 25
    .line 26
    mul-float/2addr p0, v1

    .line 27
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    const/16 v1, 0x20f

    .line 34
    .line 35
    mul-int/2addr v1, v0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/16 v1, 0x11

    .line 38
    .line 39
    :goto_0
    if-eqz v2, :cond_1

    .line 40
    .line 41
    mul-int/lit8 v1, v1, 0x1f

    .line 42
    .line 43
    mul-int/2addr v1, v2

    .line 44
    :cond_1
    if-eqz p0, :cond_2

    .line 45
    .line 46
    mul-int/lit8 v1, v1, 0x1f

    .line 47
    .line 48
    mul-int/2addr v1, p0

    .line 49
    :cond_2
    return v1
.end method

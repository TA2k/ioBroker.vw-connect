.class public final Ldn/h;
.super Ldn/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Landroid/graphics/RectF;

.field public final B:Ldn/i;

.field public final C:[F

.field public final D:Landroid/graphics/Path;

.field public final E:Ldn/e;


# direct methods
.method public constructor <init>(Lum/j;Ldn/e;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1, p2}, Ldn/b;-><init>(Lum/j;Ldn/e;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Landroid/graphics/RectF;

    .line 5
    .line 6
    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ldn/h;->A:Landroid/graphics/RectF;

    .line 10
    .line 11
    new-instance p1, Ldn/i;

    .line 12
    .line 13
    invoke-direct {p1}, Ldn/i;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Ldn/h;->B:Ldn/i;

    .line 17
    .line 18
    const/16 v0, 0x8

    .line 19
    .line 20
    new-array v0, v0, [F

    .line 21
    .line 22
    iput-object v0, p0, Ldn/h;->C:[F

    .line 23
    .line 24
    new-instance v0, Landroid/graphics/Path;

    .line 25
    .line 26
    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Ldn/h;->D:Landroid/graphics/Path;

    .line 30
    .line 31
    iput-object p2, p0, Ldn/h;->E:Ldn/e;

    .line 32
    .line 33
    const/4 p0, 0x0

    .line 34
    invoke-virtual {p1, p0}, Ldn/i;->setAlpha(I)V

    .line 35
    .line 36
    .line 37
    sget-object p0, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 38
    .line 39
    invoke-virtual {p1, p0}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 40
    .line 41
    .line 42
    iget p0, p2, Ldn/e;->l:I

    .line 43
    .line 44
    invoke-virtual {p1, p0}, Landroid/graphics/Paint;->setColor(I)V

    .line 45
    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 2

    .line 1
    invoke-super {p0, p1, p2, p3}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Ldn/h;->E:Ldn/e;

    .line 5
    .line 6
    iget p3, p2, Ldn/e;->j:I

    .line 7
    .line 8
    int-to-float p3, p3

    .line 9
    iget p2, p2, Ldn/e;->k:I

    .line 10
    .line 11
    int-to-float p2, p2

    .line 12
    iget-object v0, p0, Ldn/h;->A:Landroid/graphics/RectF;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-virtual {v0, v1, v1, p3, p2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Ldn/b;->n:Landroid/graphics/Matrix;

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, v0}, Landroid/graphics/RectF;->set(Landroid/graphics/RectF;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 9

    .line 1
    iget-object v0, p0, Ldn/h;->E:Ldn/e;

    .line 2
    .line 3
    iget v1, v0, Ldn/e;->l:I

    .line 4
    .line 5
    invoke-static {v1}, Landroid/graphics/Color;->alpha(I)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto/16 :goto_2

    .line 12
    .line 13
    :cond_0
    iget v2, v0, Ldn/e;->l:I

    .line 14
    .line 15
    iget-object v3, p0, Ldn/h;->B:Ldn/i;

    .line 16
    .line 17
    invoke-virtual {v3, v2}, Landroid/graphics/Paint;->setColor(I)V

    .line 18
    .line 19
    .line 20
    iget-object v2, p0, Ldn/b;->w:Lxm/n;

    .line 21
    .line 22
    iget-object v2, v2, Lxm/n;->j:Lxm/f;

    .line 23
    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    const/16 v2, 0x64

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    check-cast v2, Ljava/lang/Integer;

    .line 34
    .line 35
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    :goto_0
    int-to-float p3, p3

    .line 40
    const/high16 v4, 0x437f0000    # 255.0f

    .line 41
    .line 42
    div-float/2addr p3, v4

    .line 43
    int-to-float v1, v1

    .line 44
    div-float/2addr v1, v4

    .line 45
    int-to-float v2, v2

    .line 46
    mul-float/2addr v1, v2

    .line 47
    const/high16 v2, 0x42c80000    # 100.0f

    .line 48
    .line 49
    div-float/2addr v1, v2

    .line 50
    mul-float/2addr v1, p3

    .line 51
    mul-float/2addr v1, v4

    .line 52
    float-to-int p3, v1

    .line 53
    invoke-virtual {v3, p3}, Ldn/i;->setAlpha(I)V

    .line 54
    .line 55
    .line 56
    if-eqz p4, :cond_3

    .line 57
    .line 58
    iget v1, p4, Lgn/a;->d:I

    .line 59
    .line 60
    invoke-static {v1}, Landroid/graphics/Color;->alpha(I)I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-lez v1, :cond_2

    .line 65
    .line 66
    iget v1, p4, Lgn/a;->a:F

    .line 67
    .line 68
    const/4 v2, 0x1

    .line 69
    invoke-static {v1, v2}, Ljava/lang/Math;->max(FF)F

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    iget v2, p4, Lgn/a;->b:F

    .line 74
    .line 75
    iget v4, p4, Lgn/a;->c:F

    .line 76
    .line 77
    iget p4, p4, Lgn/a;->d:I

    .line 78
    .line 79
    invoke-virtual {v3, v1, v2, v4, p4}, Landroid/graphics/Paint;->setShadowLayer(FFFI)V

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_2
    invoke-virtual {v3}, Landroid/graphics/Paint;->clearShadowLayer()V

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_3
    invoke-virtual {v3}, Landroid/graphics/Paint;->clearShadowLayer()V

    .line 88
    .line 89
    .line 90
    :goto_1
    if-lez p3, :cond_4

    .line 91
    .line 92
    iget-object p3, p0, Ldn/h;->C:[F

    .line 93
    .line 94
    const/4 p4, 0x0

    .line 95
    const/4 v1, 0x0

    .line 96
    aput v1, p3, p4

    .line 97
    .line 98
    const/4 v2, 0x1

    .line 99
    aput v1, p3, v2

    .line 100
    .line 101
    iget v4, v0, Ldn/e;->j:I

    .line 102
    .line 103
    int-to-float v4, v4

    .line 104
    const/4 v5, 0x2

    .line 105
    aput v4, p3, v5

    .line 106
    .line 107
    const/4 v6, 0x3

    .line 108
    aput v1, p3, v6

    .line 109
    .line 110
    const/4 v7, 0x4

    .line 111
    aput v4, p3, v7

    .line 112
    .line 113
    iget v0, v0, Ldn/e;->k:I

    .line 114
    .line 115
    int-to-float v0, v0

    .line 116
    const/4 v4, 0x5

    .line 117
    aput v0, p3, v4

    .line 118
    .line 119
    const/4 v8, 0x6

    .line 120
    aput v1, p3, v8

    .line 121
    .line 122
    const/4 v1, 0x7

    .line 123
    aput v0, p3, v1

    .line 124
    .line 125
    invoke-virtual {p2, p3}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 126
    .line 127
    .line 128
    iget-object p0, p0, Ldn/h;->D:Landroid/graphics/Path;

    .line 129
    .line 130
    invoke-virtual {p0}, Landroid/graphics/Path;->reset()V

    .line 131
    .line 132
    .line 133
    aget p2, p3, p4

    .line 134
    .line 135
    aget v0, p3, v2

    .line 136
    .line 137
    invoke-virtual {p0, p2, v0}, Landroid/graphics/Path;->moveTo(FF)V

    .line 138
    .line 139
    .line 140
    aget p2, p3, v5

    .line 141
    .line 142
    aget v0, p3, v6

    .line 143
    .line 144
    invoke-virtual {p0, p2, v0}, Landroid/graphics/Path;->lineTo(FF)V

    .line 145
    .line 146
    .line 147
    aget p2, p3, v7

    .line 148
    .line 149
    aget v0, p3, v4

    .line 150
    .line 151
    invoke-virtual {p0, p2, v0}, Landroid/graphics/Path;->lineTo(FF)V

    .line 152
    .line 153
    .line 154
    aget p2, p3, v8

    .line 155
    .line 156
    aget v0, p3, v1

    .line 157
    .line 158
    invoke-virtual {p0, p2, v0}, Landroid/graphics/Path;->lineTo(FF)V

    .line 159
    .line 160
    .line 161
    aget p2, p3, p4

    .line 162
    .line 163
    aget p3, p3, v2

    .line 164
    .line 165
    invoke-virtual {p0, p2, p3}, Landroid/graphics/Path;->lineTo(FF)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {p0}, Landroid/graphics/Path;->close()V

    .line 169
    .line 170
    .line 171
    invoke-virtual {p1, p0, v3}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 172
    .line 173
    .line 174
    :cond_4
    :goto_2
    return-void
.end method

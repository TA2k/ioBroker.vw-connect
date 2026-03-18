.class public abstract Ljp/ae;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroid/graphics/RectF;Z)F
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    iget p0, p0, Landroid/graphics/RectF;->left:F

    .line 9
    .line 10
    return p0

    .line 11
    :cond_0
    iget p0, p0, Landroid/graphics/RectF;->right:F

    .line 12
    .line 13
    return p0
.end method

.method public static final b(Landroid/graphics/RectF;F)V
    .locals 10

    .line 1
    const/high16 v0, 0x43340000    # 180.0f

    .line 2
    .line 3
    rem-float v0, p1, v0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    cmpg-float v0, v0, v1

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/high16 v0, 0x42b40000    # 90.0f

    .line 12
    .line 13
    rem-float v0, p1, v0

    .line 14
    .line 15
    cmpg-float v0, v0, v1

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    if-nez v0, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    cmpg-float p1, p1, v0

    .line 29
    .line 30
    if-nez p1, :cond_1

    .line 31
    .line 32
    :goto_0
    return-void

    .line 33
    :cond_1
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerX()F

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    int-to-float v1, v1

    .line 42
    div-float/2addr v0, v1

    .line 43
    sub-float/2addr p1, v0

    .line 44
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerY()F

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    div-float/2addr v2, v1

    .line 57
    sub-float/2addr v0, v2

    .line 58
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerX()F

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    div-float/2addr v3, v1

    .line 71
    add-float/2addr v3, v2

    .line 72
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerY()F

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    div-float/2addr v4, v1

    .line 85
    add-float/2addr v4, v3

    .line 86
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-static {p0, p1, v0, v2, v1}, Ljp/ae;->c(Landroid/graphics/RectF;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_2
    float-to-double v2, p1

    .line 95
    invoke-static {v2, v3}, Ljava/lang/Math;->toRadians(D)D

    .line 96
    .line 97
    .line 98
    move-result-wide v2

    .line 99
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 100
    .line 101
    .line 102
    move-result-wide v4

    .line 103
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    .line 104
    .line 105
    .line 106
    move-result-wide v2

    .line 107
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 108
    .line 109
    .line 110
    move-result p1

    .line 111
    float-to-double v6, p1

    .line 112
    mul-double/2addr v6, v2

    .line 113
    invoke-static {v6, v7}, Ljava/lang/Math;->abs(D)D

    .line 114
    .line 115
    .line 116
    move-result-wide v6

    .line 117
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 118
    .line 119
    .line 120
    move-result p1

    .line 121
    float-to-double v8, p1

    .line 122
    mul-double/2addr v8, v4

    .line 123
    invoke-static {v8, v9}, Ljava/lang/Math;->abs(D)D

    .line 124
    .line 125
    .line 126
    move-result-wide v8

    .line 127
    add-double/2addr v8, v6

    .line 128
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    float-to-double v6, p1

    .line 133
    mul-double/2addr v6, v4

    .line 134
    invoke-static {v6, v7}, Ljava/lang/Math;->abs(D)D

    .line 135
    .line 136
    .line 137
    move-result-wide v4

    .line 138
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 139
    .line 140
    .line 141
    move-result p1

    .line 142
    float-to-double v6, p1

    .line 143
    mul-double/2addr v6, v2

    .line 144
    invoke-static {v6, v7}, Ljava/lang/Math;->abs(D)D

    .line 145
    .line 146
    .line 147
    move-result-wide v2

    .line 148
    add-double/2addr v2, v4

    .line 149
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerX()F

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    float-to-double v4, p1

    .line 154
    int-to-double v0, v1

    .line 155
    div-double/2addr v8, v0

    .line 156
    sub-double/2addr v4, v8

    .line 157
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerY()F

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    float-to-double v4, v4

    .line 166
    div-double/2addr v2, v0

    .line 167
    sub-double/2addr v4, v2

    .line 168
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerX()F

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    float-to-double v4, v1

    .line 177
    add-double/2addr v4, v8

    .line 178
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    invoke-virtual {p0}, Landroid/graphics/RectF;->centerY()F

    .line 183
    .line 184
    .line 185
    move-result v4

    .line 186
    float-to-double v4, v4

    .line 187
    add-double/2addr v4, v2

    .line 188
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    invoke-static {p0, p1, v0, v1, v2}, Ljp/ae;->c(Landroid/graphics/RectF;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;)V

    .line 193
    .line 194
    .line 195
    return-void
.end method

.method public static final c(Landroid/graphics/RectF;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;Ljava/lang/Number;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 15
    .line 16
    .line 17
    move-result p3

    .line 18
    invoke-virtual {p4}, Ljava/lang/Number;->floatValue()F

    .line 19
    .line 20
    .line 21
    move-result p4

    .line 22
    invoke-virtual {p0, p1, p2, p3, p4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public static final d(Landroid/graphics/RectF;FF)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroid/graphics/RectF;->left:F

    .line 7
    .line 8
    add-float/2addr v0, p1

    .line 9
    iput v0, p0, Landroid/graphics/RectF;->left:F

    .line 10
    .line 11
    iget v0, p0, Landroid/graphics/RectF;->top:F

    .line 12
    .line 13
    add-float/2addr v0, p2

    .line 14
    iput v0, p0, Landroid/graphics/RectF;->top:F

    .line 15
    .line 16
    iget v0, p0, Landroid/graphics/RectF;->right:F

    .line 17
    .line 18
    add-float/2addr v0, p1

    .line 19
    iput v0, p0, Landroid/graphics/RectF;->right:F

    .line 20
    .line 21
    iget p1, p0, Landroid/graphics/RectF;->bottom:F

    .line 22
    .line 23
    add-float/2addr p1, p2

    .line 24
    iput p1, p0, Landroid/graphics/RectF;->bottom:F

    .line 25
    .line 26
    return-void
.end method

.method public static e(I)I
    .locals 1

    .line 1
    and-int/lit8 v0, p0, 0x1

    .line 2
    .line 3
    ushr-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    neg-int v0, v0

    .line 6
    xor-int/2addr p0, v0

    .line 7
    return p0
.end method

.method public static f(J)J
    .locals 3

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    and-long/2addr v0, p0

    .line 4
    const/4 v2, 0x1

    .line 5
    ushr-long/2addr p0, v2

    .line 6
    neg-long v0, v0

    .line 7
    xor-long/2addr p0, v0

    .line 8
    return-wide p0
.end method

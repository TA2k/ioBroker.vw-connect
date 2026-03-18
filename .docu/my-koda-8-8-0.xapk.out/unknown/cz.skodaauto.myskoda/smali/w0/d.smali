.class public final Lw0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Landroid/util/Size;

.field public b:Landroid/graphics/Rect;

.field public c:I

.field public d:Landroid/graphics/Matrix;

.field public e:I

.field public f:Z

.field public g:Z

.field public h:Lw0/g;


# virtual methods
.method public final a(Landroid/util/Size;ILandroid/graphics/Rect;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lw0/d;->f()Z

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
    new-instance v0, Landroid/graphics/Matrix;

    .line 9
    .line 10
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Lw0/d;->f()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    goto :goto_0

    .line 21
    :cond_1
    new-instance v1, Landroid/graphics/Matrix;

    .line 22
    .line 23
    iget-object v2, p0, Lw0/d;->d:Landroid/graphics/Matrix;

    .line 24
    .line 25
    invoke-direct {v1, v2}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1, p2}, Lw0/d;->c(Landroid/util/Size;I)Landroid/graphics/Matrix;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {v1, p0}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 33
    .line 34
    .line 35
    move-object p0, v1

    .line 36
    :goto_0
    invoke-virtual {p0, v0}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 37
    .line 38
    .line 39
    new-instance p0, Landroid/graphics/Matrix;

    .line 40
    .line 41
    invoke-direct {p0}, Landroid/graphics/Matrix;-><init>()V

    .line 42
    .line 43
    .line 44
    new-instance p1, Landroid/graphics/RectF;

    .line 45
    .line 46
    invoke-virtual {p3}, Landroid/graphics/Rect;->width()I

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    int-to-float p2, p2

    .line 51
    invoke-virtual {p3}, Landroid/graphics/Rect;->height()I

    .line 52
    .line 53
    .line 54
    move-result p3

    .line 55
    int-to-float p3, p3

    .line 56
    const/4 v1, 0x0

    .line 57
    invoke-direct {p1, v1, v1, p2, p3}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 58
    .line 59
    .line 60
    new-instance p2, Landroid/graphics/RectF;

    .line 61
    .line 62
    const/high16 p3, 0x3f800000    # 1.0f

    .line 63
    .line 64
    invoke-direct {p2, v1, v1, p3, p3}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 65
    .line 66
    .line 67
    sget-object p3, Landroid/graphics/Matrix$ScaleToFit;->FILL:Landroid/graphics/Matrix$ScaleToFit;

    .line 68
    .line 69
    invoke-virtual {p0, p1, p2, p3}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, p0}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method public final b()Landroid/util/Size;
    .locals 2

    .line 1
    iget v0, p0, Lw0/d;->c:I

    .line 2
    .line 3
    invoke-static {v0}, Li0/f;->c(I)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Landroid/util/Size;

    .line 10
    .line 11
    iget-object v1, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 12
    .line 13
    invoke-virtual {v1}, Landroid/graphics/Rect;->height()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    iget-object p0, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    invoke-direct {v0, v1, p0}, Landroid/util/Size;-><init>(II)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_0
    new-instance v0, Landroid/util/Size;

    .line 28
    .line 29
    iget-object v1, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 30
    .line 31
    invoke-virtual {v1}, Landroid/graphics/Rect;->width()I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    iget-object p0, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 36
    .line 37
    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    invoke-direct {v0, v1, p0}, Landroid/util/Size;-><init>(II)V

    .line 42
    .line 43
    .line 44
    return-object v0
.end method

.method public final c(Landroid/util/Size;I)Landroid/graphics/Matrix;
    .locals 7

    .line 1
    invoke-virtual {p0}, Lw0/d;->f()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lw0/d;->b()Landroid/util/Size;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-static {p1, v1, v0}, Li0/f;->d(Landroid/util/Size;ZLandroid/util/Size;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v2, 0x0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    new-instance p2, Landroid/graphics/RectF;

    .line 22
    .line 23
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    int-to-float v0, v0

    .line 28
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    int-to-float p1, p1

    .line 33
    invoke-direct {p2, v2, v2, v0, p1}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 34
    .line 35
    .line 36
    goto/16 :goto_3

    .line 37
    .line 38
    :cond_0
    new-instance v0, Landroid/graphics/RectF;

    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    int-to-float v3, v3

    .line 45
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    int-to-float v4, v4

    .line 50
    invoke-direct {v0, v2, v2, v3, v4}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Lw0/d;->b()Landroid/util/Size;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    new-instance v4, Landroid/graphics/RectF;

    .line 58
    .line 59
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 60
    .line 61
    .line 62
    move-result v5

    .line 63
    int-to-float v5, v5

    .line 64
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    int-to-float v3, v3

    .line 69
    invoke-direct {v4, v2, v2, v5, v3}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 70
    .line 71
    .line 72
    new-instance v2, Landroid/graphics/Matrix;

    .line 73
    .line 74
    invoke-direct {v2}, Landroid/graphics/Matrix;-><init>()V

    .line 75
    .line 76
    .line 77
    iget-object v3, p0, Lw0/d;->h:Lw0/g;

    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    if-eqz v5, :cond_3

    .line 84
    .line 85
    if-eq v5, v1, :cond_2

    .line 86
    .line 87
    const/4 v6, 0x2

    .line 88
    if-eq v5, v6, :cond_1

    .line 89
    .line 90
    const/4 v6, 0x3

    .line 91
    if-eq v5, v6, :cond_3

    .line 92
    .line 93
    const/4 v6, 0x4

    .line 94
    if-eq v5, v6, :cond_2

    .line 95
    .line 96
    const/4 v6, 0x5

    .line 97
    if-eq v5, v6, :cond_1

    .line 98
    .line 99
    new-instance v5, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    const-string v6, "Unexpected crop rect: "

    .line 102
    .line 103
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    const-string v6, "PreviewTransform"

    .line 114
    .line 115
    invoke-static {v6, v5}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    sget-object v5, Landroid/graphics/Matrix$ScaleToFit;->FILL:Landroid/graphics/Matrix$ScaleToFit;

    .line 119
    .line 120
    goto :goto_0

    .line 121
    :cond_1
    sget-object v5, Landroid/graphics/Matrix$ScaleToFit;->END:Landroid/graphics/Matrix$ScaleToFit;

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_2
    sget-object v5, Landroid/graphics/Matrix$ScaleToFit;->CENTER:Landroid/graphics/Matrix$ScaleToFit;

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_3
    sget-object v5, Landroid/graphics/Matrix$ScaleToFit;->START:Landroid/graphics/Matrix$ScaleToFit;

    .line 128
    .line 129
    :goto_0
    sget-object v6, Lw0/g;->g:Lw0/g;

    .line 130
    .line 131
    if-eq v3, v6, :cond_5

    .line 132
    .line 133
    sget-object v6, Lw0/g;->f:Lw0/g;

    .line 134
    .line 135
    if-eq v3, v6, :cond_5

    .line 136
    .line 137
    sget-object v6, Lw0/g;->h:Lw0/g;

    .line 138
    .line 139
    if-ne v3, v6, :cond_4

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_4
    invoke-virtual {v2, v0, v4, v5}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 143
    .line 144
    .line 145
    invoke-virtual {v2, v2}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 146
    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_5
    :goto_1
    invoke-virtual {v2, v4, v0, v5}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 150
    .line 151
    .line 152
    :goto_2
    invoke-virtual {v2, v4}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 153
    .line 154
    .line 155
    if-ne p2, v1, :cond_6

    .line 156
    .line 157
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 158
    .line 159
    .line 160
    move-result p1

    .line 161
    int-to-float p1, p1

    .line 162
    const/high16 p2, 0x40000000    # 2.0f

    .line 163
    .line 164
    div-float/2addr p1, p2

    .line 165
    new-instance p2, Landroid/graphics/RectF;

    .line 166
    .line 167
    add-float/2addr p1, p1

    .line 168
    iget v0, v4, Landroid/graphics/RectF;->right:F

    .line 169
    .line 170
    sub-float v0, p1, v0

    .line 171
    .line 172
    iget v1, v4, Landroid/graphics/RectF;->top:F

    .line 173
    .line 174
    iget v2, v4, Landroid/graphics/RectF;->left:F

    .line 175
    .line 176
    sub-float/2addr p1, v2

    .line 177
    iget v2, v4, Landroid/graphics/RectF;->bottom:F

    .line 178
    .line 179
    invoke-direct {p2, v0, v1, p1, v2}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 180
    .line 181
    .line 182
    goto :goto_3

    .line 183
    :cond_6
    move-object p2, v4

    .line 184
    :goto_3
    new-instance p1, Landroid/graphics/RectF;

    .line 185
    .line 186
    iget-object v0, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 187
    .line 188
    invoke-direct {p1, v0}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 189
    .line 190
    .line 191
    iget v0, p0, Lw0/d;->c:I

    .line 192
    .line 193
    const/4 v1, 0x0

    .line 194
    invoke-static {p1, p2, v0, v1}, Li0/f;->a(Landroid/graphics/RectF;Landroid/graphics/RectF;IZ)Landroid/graphics/Matrix;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    iget-boolean p2, p0, Lw0/d;->f:Z

    .line 199
    .line 200
    if-eqz p2, :cond_8

    .line 201
    .line 202
    iget-boolean p2, p0, Lw0/d;->g:Z

    .line 203
    .line 204
    if-eqz p2, :cond_8

    .line 205
    .line 206
    iget p2, p0, Lw0/d;->c:I

    .line 207
    .line 208
    invoke-static {p2}, Li0/f;->c(I)Z

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    const/high16 v0, -0x40800000    # -1.0f

    .line 213
    .line 214
    const/high16 v1, 0x3f800000    # 1.0f

    .line 215
    .line 216
    if-eqz p2, :cond_7

    .line 217
    .line 218
    iget-object p2, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 219
    .line 220
    invoke-virtual {p2}, Landroid/graphics/Rect;->centerX()I

    .line 221
    .line 222
    .line 223
    move-result p2

    .line 224
    int-to-float p2, p2

    .line 225
    iget-object p0, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 226
    .line 227
    invoke-virtual {p0}, Landroid/graphics/Rect;->centerY()I

    .line 228
    .line 229
    .line 230
    move-result p0

    .line 231
    int-to-float p0, p0

    .line 232
    invoke-virtual {p1, v1, v0, p2, p0}, Landroid/graphics/Matrix;->preScale(FFFF)Z

    .line 233
    .line 234
    .line 235
    return-object p1

    .line 236
    :cond_7
    iget-object p2, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 237
    .line 238
    invoke-virtual {p2}, Landroid/graphics/Rect;->centerX()I

    .line 239
    .line 240
    .line 241
    move-result p2

    .line 242
    int-to-float p2, p2

    .line 243
    iget-object p0, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 244
    .line 245
    invoke-virtual {p0}, Landroid/graphics/Rect;->centerY()I

    .line 246
    .line 247
    .line 248
    move-result p0

    .line 249
    int-to-float p0, p0

    .line 250
    invoke-virtual {p1, v0, v1, p2, p0}, Landroid/graphics/Matrix;->preScale(FFFF)Z

    .line 251
    .line 252
    .line 253
    :cond_8
    return-object p1
.end method

.method public final d()Landroid/graphics/Matrix;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lw0/d;->f()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 7
    .line 8
    .line 9
    new-instance v0, Landroid/graphics/RectF;

    .line 10
    .line 11
    iget-object v1, p0, Lw0/d;->a:Landroid/util/Size;

    .line 12
    .line 13
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    int-to-float v1, v1

    .line 18
    iget-object v2, p0, Lw0/d;->a:Landroid/util/Size;

    .line 19
    .line 20
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    int-to-float v2, v2

    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-direct {v0, v3, v3, v1, v2}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 27
    .line 28
    .line 29
    iget-boolean v1, p0, Lw0/d;->g:Z

    .line 30
    .line 31
    if-nez v1, :cond_0

    .line 32
    .line 33
    iget p0, p0, Lw0/d;->c:I

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget p0, p0, Lw0/d;->e:I

    .line 37
    .line 38
    invoke-static {p0}, Llp/h1;->c(I)I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    neg-int p0, p0

    .line 43
    :goto_0
    const/4 v1, 0x0

    .line 44
    invoke-static {v0, v0, p0, v1}, Li0/f;->a(Landroid/graphics/RectF;Landroid/graphics/RectF;IZ)Landroid/graphics/Matrix;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public final e(Landroid/util/Size;I)Landroid/graphics/RectF;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lw0/d;->f()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1, p2}, Lw0/d;->c(Landroid/util/Size;I)Landroid/graphics/Matrix;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    new-instance p2, Landroid/graphics/RectF;

    .line 14
    .line 15
    iget-object v0, p0, Lw0/d;->a:Landroid/util/Size;

    .line 16
    .line 17
    invoke-virtual {v0}, Landroid/util/Size;->getWidth()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    int-to-float v0, v0

    .line 22
    iget-object p0, p0, Lw0/d;->a:Landroid/util/Size;

    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    int-to-float p0, p0

    .line 29
    const/4 v1, 0x0

    .line 30
    invoke-direct {p2, v1, v1, v0, p0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, p2}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 34
    .line 35
    .line 36
    return-object p2
.end method

.method public final f()Z
    .locals 4

    .line 1
    iget-boolean v0, p0, Lw0/d;->g:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget v0, p0, Lw0/d;->e:I

    .line 8
    .line 9
    const/4 v3, -0x1

    .line 10
    if-eq v0, v3, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v0, v2

    .line 14
    goto :goto_1

    .line 15
    :cond_1
    :goto_0
    move v0, v1

    .line 16
    :goto_1
    iget-object v3, p0, Lw0/d;->b:Landroid/graphics/Rect;

    .line 17
    .line 18
    if-eqz v3, :cond_2

    .line 19
    .line 20
    iget-object p0, p0, Lw0/d;->a:Landroid/util/Size;

    .line 21
    .line 22
    if-eqz p0, :cond_2

    .line 23
    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    return v1

    .line 27
    :cond_2
    return v2
.end method

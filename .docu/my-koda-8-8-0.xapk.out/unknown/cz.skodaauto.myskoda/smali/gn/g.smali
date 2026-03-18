.class public final Lgn/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final B:Landroid/graphics/Matrix;


# instance fields
.field public A:Lgn/a;

.field public a:Landroid/graphics/Canvas;

.field public b:Lb11/a;

.field public c:I

.field public d:Landroid/graphics/RectF;

.field public e:Landroid/graphics/RectF;

.field public f:Landroid/graphics/Rect;

.field public g:Landroid/graphics/RectF;

.field public h:Landroid/graphics/RectF;

.field public i:Landroid/graphics/Rect;

.field public j:Landroid/graphics/RectF;

.field public k:Ldn/i;

.field public l:Landroid/graphics/Bitmap;

.field public m:Landroid/graphics/Canvas;

.field public n:Landroid/graphics/Rect;

.field public o:Ldn/i;

.field public p:Landroid/graphics/Matrix;

.field public q:[F

.field public r:Landroid/graphics/Bitmap;

.field public s:Landroid/graphics/Bitmap;

.field public t:Landroid/graphics/Canvas;

.field public u:Landroid/graphics/Canvas;

.field public v:Ldn/i;

.field public w:Landroid/graphics/BlurMaskFilter;

.field public x:F

.field public y:Landroid/graphics/RenderNode;

.field public z:Landroid/graphics/RenderNode;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lgn/g;->B:Landroid/graphics/Matrix;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lgn/g;->x:F

    .line 6
    .line 7
    return-void
.end method

.method public static a(Landroid/graphics/RectF;Landroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;
    .locals 6

    .line 1
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    float-to-double v0, v0

    .line 6
    const-wide v2, 0x3ff0cccccccccccdL    # 1.05

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    mul-double/2addr v0, v2

    .line 12
    invoke-static {v0, v1}, Ljava/lang/Math;->ceil(D)D

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    double-to-int v0, v0

    .line 17
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    float-to-double v4, p0

    .line 22
    mul-double/2addr v4, v2

    .line 23
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 24
    .line 25
    .line 26
    move-result-wide v1

    .line 27
    double-to-int p0, v1

    .line 28
    const/4 v1, 0x1

    .line 29
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    invoke-static {p0, v1}, Ljava/lang/Math;->max(II)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    invoke-static {v0, p0, p1}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method public static d(Landroid/graphics/Bitmap;Landroid/graphics/RectF;)Z
    .locals 3

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p1}, Landroid/graphics/RectF;->width()F

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    int-to-float v1, v1

    .line 13
    cmpl-float v0, v0, v1

    .line 14
    .line 15
    if-gez v0, :cond_3

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/graphics/RectF;->height()F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    int-to-float v1, v1

    .line 26
    cmpl-float v0, v0, v1

    .line 27
    .line 28
    if-ltz v0, :cond_1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    invoke-virtual {p1}, Landroid/graphics/RectF;->width()F

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    int-to-float v1, v1

    .line 40
    const/high16 v2, 0x3f400000    # 0.75f

    .line 41
    .line 42
    mul-float/2addr v1, v2

    .line 43
    cmpg-float v0, v0, v1

    .line 44
    .line 45
    if-ltz v0, :cond_3

    .line 46
    .line 47
    invoke-virtual {p1}, Landroid/graphics/RectF;->height()F

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    int-to-float p0, p0

    .line 56
    mul-float/2addr p0, v2

    .line 57
    cmpg-float p0, p1, p0

    .line 58
    .line 59
    if-gez p0, :cond_2

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    const/4 p0, 0x0

    .line 63
    return p0

    .line 64
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 65
    return p0
.end method


# virtual methods
.method public final b(Landroid/graphics/RectF;Lgn/a;)Landroid/graphics/RectF;
    .locals 4

    .line 1
    iget-object v0, p0, Lgn/g;->e:Landroid/graphics/RectF;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroid/graphics/RectF;

    .line 6
    .line 7
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lgn/g;->e:Landroid/graphics/RectF;

    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lgn/g;->g:Landroid/graphics/RectF;

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    new-instance v0, Landroid/graphics/RectF;

    .line 17
    .line 18
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lgn/g;->g:Landroid/graphics/RectF;

    .line 22
    .line 23
    :cond_1
    iget-object v0, p0, Lgn/g;->e:Landroid/graphics/RectF;

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Landroid/graphics/RectF;->set(Landroid/graphics/RectF;)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lgn/g;->e:Landroid/graphics/RectF;

    .line 29
    .line 30
    iget v1, p1, Landroid/graphics/RectF;->left:F

    .line 31
    .line 32
    iget v2, p2, Lgn/a;->b:F

    .line 33
    .line 34
    add-float/2addr v1, v2

    .line 35
    iget v2, p1, Landroid/graphics/RectF;->top:F

    .line 36
    .line 37
    iget v3, p2, Lgn/a;->c:F

    .line 38
    .line 39
    add-float/2addr v2, v3

    .line 40
    invoke-virtual {v0, v1, v2}, Landroid/graphics/RectF;->offsetTo(FF)V

    .line 41
    .line 42
    .line 43
    iget-object v0, p0, Lgn/g;->e:Landroid/graphics/RectF;

    .line 44
    .line 45
    iget p2, p2, Lgn/a;->a:F

    .line 46
    .line 47
    neg-float v1, p2

    .line 48
    neg-float p2, p2

    .line 49
    invoke-virtual {v0, v1, p2}, Landroid/graphics/RectF;->inset(FF)V

    .line 50
    .line 51
    .line 52
    iget-object p2, p0, Lgn/g;->g:Landroid/graphics/RectF;

    .line 53
    .line 54
    invoke-virtual {p2, p1}, Landroid/graphics/RectF;->set(Landroid/graphics/RectF;)V

    .line 55
    .line 56
    .line 57
    iget-object p1, p0, Lgn/g;->e:Landroid/graphics/RectF;

    .line 58
    .line 59
    iget-object p2, p0, Lgn/g;->g:Landroid/graphics/RectF;

    .line 60
    .line 61
    invoke-virtual {p1, p2}, Landroid/graphics/RectF;->union(Landroid/graphics/RectF;)V

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Lgn/g;->e:Landroid/graphics/RectF;

    .line 65
    .line 66
    return-object p0
.end method

.method public final c()V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 4
    .line 5
    if-eqz v1, :cond_1f

    .line 6
    .line 7
    iget-object v1, v0, Lgn/g;->b:Lb11/a;

    .line 8
    .line 9
    if-eqz v1, :cond_1f

    .line 10
    .line 11
    iget-object v1, v0, Lgn/g;->q:[F

    .line 12
    .line 13
    if-eqz v1, :cond_1f

    .line 14
    .line 15
    iget-object v1, v0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 16
    .line 17
    if-eqz v1, :cond_1f

    .line 18
    .line 19
    iget v1, v0, Lgn/g;->c:I

    .line 20
    .line 21
    invoke-static {v1}, Lu/w;->o(I)I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v2, 0x0

    .line 26
    if-eqz v1, :cond_1e

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    if-eq v1, v3, :cond_1d

    .line 30
    .line 31
    const/4 v4, 0x2

    .line 32
    const/high16 v5, 0x40000000    # 2.0f

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    const/4 v7, 0x4

    .line 36
    const/high16 v8, 0x3f800000    # 1.0f

    .line 37
    .line 38
    const/4 v9, 0x0

    .line 39
    if-eq v1, v4, :cond_9

    .line 40
    .line 41
    const/4 v3, 0x3

    .line 42
    if-eq v1, v3, :cond_0

    .line 43
    .line 44
    goto/16 :goto_8

    .line 45
    .line 46
    :cond_0
    iget-object v1, v0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 47
    .line 48
    if-eqz v1, :cond_8

    .line 49
    .line 50
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 51
    .line 52
    iget-object v3, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 53
    .line 54
    invoke-virtual {v3}, Landroid/graphics/Canvas;->save()I

    .line 55
    .line 56
    .line 57
    iget-object v3, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 58
    .line 59
    iget-object v4, v0, Lgn/g;->q:[F

    .line 60
    .line 61
    aget v10, v4, v9

    .line 62
    .line 63
    div-float v10, v8, v10

    .line 64
    .line 65
    aget v4, v4, v7

    .line 66
    .line 67
    div-float v4, v8, v4

    .line 68
    .line 69
    invoke-virtual {v3, v10, v4}, Landroid/graphics/Canvas;->scale(FF)V

    .line 70
    .line 71
    .line 72
    iget-object v3, v0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 73
    .line 74
    invoke-virtual {v3}, Landroid/graphics/RenderNode;->endRecording()V

    .line 75
    .line 76
    .line 77
    iget-object v3, v0, Lgn/g;->b:Lb11/a;

    .line 78
    .line 79
    invoke-virtual {v3}, Lb11/a;->c()Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-eqz v3, :cond_7

    .line 84
    .line 85
    iget-object v3, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 86
    .line 87
    iget-object v4, v0, Lgn/g;->b:Lb11/a;

    .line 88
    .line 89
    iget-object v4, v4, Lb11/a;->f:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v4, Lgn/a;

    .line 92
    .line 93
    iget-object v10, v0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 94
    .line 95
    if-eqz v10, :cond_6

    .line 96
    .line 97
    iget-object v10, v0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 98
    .line 99
    if-eqz v10, :cond_6

    .line 100
    .line 101
    const/16 v10, 0x1f

    .line 102
    .line 103
    if-lt v1, v10, :cond_5

    .line 104
    .line 105
    iget-object v1, v0, Lgn/g;->q:[F

    .line 106
    .line 107
    if-eqz v1, :cond_1

    .line 108
    .line 109
    aget v10, v1, v9

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_1
    move v10, v8

    .line 113
    :goto_0
    if-eqz v1, :cond_2

    .line 114
    .line 115
    aget v8, v1, v7

    .line 116
    .line 117
    :cond_2
    iget-object v1, v0, Lgn/g;->A:Lgn/a;

    .line 118
    .line 119
    if-eqz v1, :cond_3

    .line 120
    .line 121
    iget v7, v4, Lgn/a;->a:F

    .line 122
    .line 123
    iget v11, v1, Lgn/a;->a:F

    .line 124
    .line 125
    cmpl-float v7, v7, v11

    .line 126
    .line 127
    if-nez v7, :cond_3

    .line 128
    .line 129
    iget v7, v4, Lgn/a;->b:F

    .line 130
    .line 131
    iget v11, v1, Lgn/a;->b:F

    .line 132
    .line 133
    cmpl-float v7, v7, v11

    .line 134
    .line 135
    if-nez v7, :cond_3

    .line 136
    .line 137
    iget v7, v4, Lgn/a;->c:F

    .line 138
    .line 139
    iget v11, v1, Lgn/a;->c:F

    .line 140
    .line 141
    cmpl-float v7, v7, v11

    .line 142
    .line 143
    if-nez v7, :cond_3

    .line 144
    .line 145
    iget v7, v4, Lgn/a;->d:I

    .line 146
    .line 147
    iget v1, v1, Lgn/a;->d:I

    .line 148
    .line 149
    if-ne v7, v1, :cond_3

    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_3
    new-instance v1, Landroid/graphics/PorterDuffColorFilter;

    .line 153
    .line 154
    iget v7, v4, Lgn/a;->d:I

    .line 155
    .line 156
    sget-object v11, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    .line 157
    .line 158
    invoke-direct {v1, v7, v11}, Landroid/graphics/PorterDuffColorFilter;-><init>(ILandroid/graphics/PorterDuff$Mode;)V

    .line 159
    .line 160
    .line 161
    invoke-static {v1}, Lc4/a;->i(Landroid/graphics/PorterDuffColorFilter;)Landroid/graphics/RenderEffect;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    iget v7, v4, Lgn/a;->a:F

    .line 166
    .line 167
    cmpl-float v6, v7, v6

    .line 168
    .line 169
    if-lez v6, :cond_4

    .line 170
    .line 171
    add-float v6, v10, v8

    .line 172
    .line 173
    mul-float/2addr v6, v7

    .line 174
    div-float/2addr v6, v5

    .line 175
    sget-object v5, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 176
    .line 177
    invoke-static {v6, v6, v1}, Lc4/a;->g(FFLandroid/graphics/RenderEffect;)Landroid/graphics/RenderEffect;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    :cond_4
    iget-object v5, v0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 182
    .line 183
    invoke-static {v5, v1}, Lc4/a;->t(Landroid/graphics/RenderNode;Landroid/graphics/RenderEffect;)V

    .line 184
    .line 185
    .line 186
    iput-object v4, v0, Lgn/g;->A:Lgn/a;

    .line 187
    .line 188
    :goto_1
    iget-object v1, v0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 189
    .line 190
    invoke-virtual {v0, v1, v4}, Lgn/g;->b(Landroid/graphics/RectF;Lgn/a;)Landroid/graphics/RectF;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    new-instance v5, Landroid/graphics/RectF;

    .line 195
    .line 196
    iget v6, v1, Landroid/graphics/RectF;->left:F

    .line 197
    .line 198
    mul-float/2addr v6, v10

    .line 199
    iget v7, v1, Landroid/graphics/RectF;->top:F

    .line 200
    .line 201
    mul-float/2addr v7, v8

    .line 202
    iget v11, v1, Landroid/graphics/RectF;->right:F

    .line 203
    .line 204
    mul-float/2addr v11, v10

    .line 205
    iget v1, v1, Landroid/graphics/RectF;->bottom:F

    .line 206
    .line 207
    mul-float/2addr v1, v8

    .line 208
    invoke-direct {v5, v6, v7, v11, v1}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 209
    .line 210
    .line 211
    iget-object v1, v0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 212
    .line 213
    invoke-virtual {v5}, Landroid/graphics/RectF;->width()F

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    float-to-int v6, v6

    .line 218
    invoke-virtual {v5}, Landroid/graphics/RectF;->height()F

    .line 219
    .line 220
    .line 221
    move-result v7

    .line 222
    float-to-int v7, v7

    .line 223
    invoke-virtual {v1, v9, v9, v6, v7}, Landroid/graphics/RenderNode;->setPosition(IIII)Z

    .line 224
    .line 225
    .line 226
    iget-object v1, v0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 227
    .line 228
    invoke-virtual {v5}, Landroid/graphics/RectF;->width()F

    .line 229
    .line 230
    .line 231
    move-result v6

    .line 232
    float-to-int v6, v6

    .line 233
    invoke-virtual {v5}, Landroid/graphics/RectF;->height()F

    .line 234
    .line 235
    .line 236
    move-result v7

    .line 237
    float-to-int v7, v7

    .line 238
    invoke-virtual {v1, v6, v7}, Landroid/graphics/RenderNode;->beginRecording(II)Landroid/graphics/RecordingCanvas;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    iget v6, v5, Landroid/graphics/RectF;->left:F

    .line 243
    .line 244
    neg-float v6, v6

    .line 245
    iget v7, v4, Lgn/a;->b:F

    .line 246
    .line 247
    mul-float/2addr v7, v10

    .line 248
    add-float/2addr v7, v6

    .line 249
    iget v6, v5, Landroid/graphics/RectF;->top:F

    .line 250
    .line 251
    neg-float v6, v6

    .line 252
    iget v4, v4, Lgn/a;->c:F

    .line 253
    .line 254
    mul-float/2addr v4, v8

    .line 255
    add-float/2addr v4, v6

    .line 256
    invoke-virtual {v1, v7, v4}, Landroid/graphics/Canvas;->translate(FF)V

    .line 257
    .line 258
    .line 259
    iget-object v4, v0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 260
    .line 261
    invoke-virtual {v1, v4}, Landroid/graphics/Canvas;->drawRenderNode(Landroid/graphics/RenderNode;)V

    .line 262
    .line 263
    .line 264
    iget-object v1, v0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 265
    .line 266
    invoke-virtual {v1}, Landroid/graphics/RenderNode;->endRecording()V

    .line 267
    .line 268
    .line 269
    invoke-virtual {v3}, Landroid/graphics/Canvas;->save()I

    .line 270
    .line 271
    .line 272
    iget v1, v5, Landroid/graphics/RectF;->left:F

    .line 273
    .line 274
    iget v4, v5, Landroid/graphics/RectF;->top:F

    .line 275
    .line 276
    invoke-virtual {v3, v1, v4}, Landroid/graphics/Canvas;->translate(FF)V

    .line 277
    .line 278
    .line 279
    iget-object v1, v0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 280
    .line 281
    invoke-virtual {v3, v1}, Landroid/graphics/Canvas;->drawRenderNode(Landroid/graphics/RenderNode;)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v3}, Landroid/graphics/Canvas;->restore()V

    .line 285
    .line 286
    .line 287
    goto :goto_2

    .line 288
    :cond_5
    new-instance v0, Ljava/lang/RuntimeException;

    .line 289
    .line 290
    const-string v1, "RenderEffect is not supported on API level <31"

    .line 291
    .line 292
    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    throw v0

    .line 296
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 297
    .line 298
    const-string v1, "Cannot render to render node outside a start()/finish() block"

    .line 299
    .line 300
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    throw v0

    .line 304
    :cond_7
    :goto_2
    iget-object v1, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 305
    .line 306
    iget-object v3, v0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 307
    .line 308
    invoke-virtual {v1, v3}, Landroid/graphics/Canvas;->drawRenderNode(Landroid/graphics/RenderNode;)V

    .line 309
    .line 310
    .line 311
    iget-object v1, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 312
    .line 313
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 314
    .line 315
    .line 316
    goto/16 :goto_8

    .line 317
    .line 318
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 319
    .line 320
    const-string v1, "RenderNode is not ready; should\'ve been initialized at start() time"

    .line 321
    .line 322
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    throw v0

    .line 326
    :cond_9
    iget-object v1, v0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 327
    .line 328
    if-eqz v1, :cond_1c

    .line 329
    .line 330
    iget-object v1, v0, Lgn/g;->b:Lb11/a;

    .line 331
    .line 332
    invoke-virtual {v1}, Lb11/a;->c()Z

    .line 333
    .line 334
    .line 335
    move-result v1

    .line 336
    if-eqz v1, :cond_1a

    .line 337
    .line 338
    iget-object v1, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 339
    .line 340
    iget-object v4, v0, Lgn/g;->b:Lb11/a;

    .line 341
    .line 342
    iget-object v4, v4, Lb11/a;->f:Ljava/lang/Object;

    .line 343
    .line 344
    check-cast v4, Lgn/a;

    .line 345
    .line 346
    iget-object v10, v0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 347
    .line 348
    if-eqz v10, :cond_19

    .line 349
    .line 350
    iget-object v11, v0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 351
    .line 352
    if-eqz v11, :cond_19

    .line 353
    .line 354
    invoke-virtual {v0, v10, v4}, Lgn/g;->b(Landroid/graphics/RectF;Lgn/a;)Landroid/graphics/RectF;

    .line 355
    .line 356
    .line 357
    move-result-object v10

    .line 358
    iget-object v11, v0, Lgn/g;->f:Landroid/graphics/Rect;

    .line 359
    .line 360
    if-nez v11, :cond_a

    .line 361
    .line 362
    new-instance v11, Landroid/graphics/Rect;

    .line 363
    .line 364
    invoke-direct {v11}, Landroid/graphics/Rect;-><init>()V

    .line 365
    .line 366
    .line 367
    iput-object v11, v0, Lgn/g;->f:Landroid/graphics/Rect;

    .line 368
    .line 369
    :cond_a
    iget-object v11, v0, Lgn/g;->f:Landroid/graphics/Rect;

    .line 370
    .line 371
    iget v12, v10, Landroid/graphics/RectF;->left:F

    .line 372
    .line 373
    float-to-double v12, v12

    .line 374
    invoke-static {v12, v13}, Ljava/lang/Math;->floor(D)D

    .line 375
    .line 376
    .line 377
    move-result-wide v12

    .line 378
    double-to-int v12, v12

    .line 379
    iget v13, v10, Landroid/graphics/RectF;->top:F

    .line 380
    .line 381
    float-to-double v13, v13

    .line 382
    invoke-static {v13, v14}, Ljava/lang/Math;->floor(D)D

    .line 383
    .line 384
    .line 385
    move-result-wide v13

    .line 386
    double-to-int v13, v13

    .line 387
    iget v14, v10, Landroid/graphics/RectF;->right:F

    .line 388
    .line 389
    float-to-double v14, v14

    .line 390
    invoke-static {v14, v15}, Ljava/lang/Math;->ceil(D)D

    .line 391
    .line 392
    .line 393
    move-result-wide v14

    .line 394
    double-to-int v14, v14

    .line 395
    iget v15, v10, Landroid/graphics/RectF;->bottom:F

    .line 396
    .line 397
    move/from16 v17, v5

    .line 398
    .line 399
    move/from16 v16, v6

    .line 400
    .line 401
    float-to-double v5, v15

    .line 402
    invoke-static {v5, v6}, Ljava/lang/Math;->ceil(D)D

    .line 403
    .line 404
    .line 405
    move-result-wide v5

    .line 406
    double-to-int v5, v5

    .line 407
    invoke-virtual {v11, v12, v13, v14, v5}, Landroid/graphics/Rect;->set(IIII)V

    .line 408
    .line 409
    .line 410
    iget-object v5, v0, Lgn/g;->q:[F

    .line 411
    .line 412
    if-eqz v5, :cond_b

    .line 413
    .line 414
    aget v6, v5, v9

    .line 415
    .line 416
    goto :goto_3

    .line 417
    :cond_b
    move v6, v8

    .line 418
    :goto_3
    if-eqz v5, :cond_c

    .line 419
    .line 420
    aget v8, v5, v7

    .line 421
    .line 422
    :cond_c
    iget-object v5, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 423
    .line 424
    if-nez v5, :cond_d

    .line 425
    .line 426
    new-instance v5, Landroid/graphics/RectF;

    .line 427
    .line 428
    invoke-direct {v5}, Landroid/graphics/RectF;-><init>()V

    .line 429
    .line 430
    .line 431
    iput-object v5, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 432
    .line 433
    :cond_d
    iget-object v5, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 434
    .line 435
    iget v11, v10, Landroid/graphics/RectF;->left:F

    .line 436
    .line 437
    mul-float/2addr v11, v6

    .line 438
    iget v12, v10, Landroid/graphics/RectF;->top:F

    .line 439
    .line 440
    mul-float/2addr v12, v8

    .line 441
    iget v13, v10, Landroid/graphics/RectF;->right:F

    .line 442
    .line 443
    mul-float/2addr v13, v6

    .line 444
    iget v14, v10, Landroid/graphics/RectF;->bottom:F

    .line 445
    .line 446
    mul-float/2addr v14, v8

    .line 447
    invoke-virtual {v5, v11, v12, v13, v14}, Landroid/graphics/RectF;->set(FFFF)V

    .line 448
    .line 449
    .line 450
    iget-object v5, v0, Lgn/g;->i:Landroid/graphics/Rect;

    .line 451
    .line 452
    if-nez v5, :cond_e

    .line 453
    .line 454
    new-instance v5, Landroid/graphics/Rect;

    .line 455
    .line 456
    invoke-direct {v5}, Landroid/graphics/Rect;-><init>()V

    .line 457
    .line 458
    .line 459
    iput-object v5, v0, Lgn/g;->i:Landroid/graphics/Rect;

    .line 460
    .line 461
    :cond_e
    iget-object v5, v0, Lgn/g;->i:Landroid/graphics/Rect;

    .line 462
    .line 463
    iget-object v11, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 464
    .line 465
    invoke-virtual {v11}, Landroid/graphics/RectF;->width()F

    .line 466
    .line 467
    .line 468
    move-result v11

    .line 469
    invoke-static {v11}, Ljava/lang/Math;->round(F)I

    .line 470
    .line 471
    .line 472
    move-result v11

    .line 473
    iget-object v12, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 474
    .line 475
    invoke-virtual {v12}, Landroid/graphics/RectF;->height()F

    .line 476
    .line 477
    .line 478
    move-result v12

    .line 479
    invoke-static {v12}, Ljava/lang/Math;->round(F)I

    .line 480
    .line 481
    .line 482
    move-result v12

    .line 483
    invoke-virtual {v5, v9, v9, v11, v12}, Landroid/graphics/Rect;->set(IIII)V

    .line 484
    .line 485
    .line 486
    iget-object v5, v0, Lgn/g;->r:Landroid/graphics/Bitmap;

    .line 487
    .line 488
    iget-object v11, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 489
    .line 490
    invoke-static {v5, v11}, Lgn/g;->d(Landroid/graphics/Bitmap;Landroid/graphics/RectF;)Z

    .line 491
    .line 492
    .line 493
    move-result v5

    .line 494
    if-eqz v5, :cond_11

    .line 495
    .line 496
    iget-object v5, v0, Lgn/g;->r:Landroid/graphics/Bitmap;

    .line 497
    .line 498
    if-eqz v5, :cond_f

    .line 499
    .line 500
    invoke-virtual {v5}, Landroid/graphics/Bitmap;->recycle()V

    .line 501
    .line 502
    .line 503
    :cond_f
    iget-object v5, v0, Lgn/g;->s:Landroid/graphics/Bitmap;

    .line 504
    .line 505
    if-eqz v5, :cond_10

    .line 506
    .line 507
    invoke-virtual {v5}, Landroid/graphics/Bitmap;->recycle()V

    .line 508
    .line 509
    .line 510
    :cond_10
    iget-object v5, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 511
    .line 512
    sget-object v11, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 513
    .line 514
    invoke-static {v5, v11}, Lgn/g;->a(Landroid/graphics/RectF;Landroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 515
    .line 516
    .line 517
    move-result-object v5

    .line 518
    iput-object v5, v0, Lgn/g;->r:Landroid/graphics/Bitmap;

    .line 519
    .line 520
    iget-object v5, v0, Lgn/g;->h:Landroid/graphics/RectF;

    .line 521
    .line 522
    sget-object v11, Landroid/graphics/Bitmap$Config;->ALPHA_8:Landroid/graphics/Bitmap$Config;

    .line 523
    .line 524
    invoke-static {v5, v11}, Lgn/g;->a(Landroid/graphics/RectF;Landroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 525
    .line 526
    .line 527
    move-result-object v5

    .line 528
    iput-object v5, v0, Lgn/g;->s:Landroid/graphics/Bitmap;

    .line 529
    .line 530
    new-instance v5, Landroid/graphics/Canvas;

    .line 531
    .line 532
    iget-object v11, v0, Lgn/g;->r:Landroid/graphics/Bitmap;

    .line 533
    .line 534
    invoke-direct {v5, v11}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 535
    .line 536
    .line 537
    iput-object v5, v0, Lgn/g;->t:Landroid/graphics/Canvas;

    .line 538
    .line 539
    new-instance v5, Landroid/graphics/Canvas;

    .line 540
    .line 541
    iget-object v11, v0, Lgn/g;->s:Landroid/graphics/Bitmap;

    .line 542
    .line 543
    invoke-direct {v5, v11}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 544
    .line 545
    .line 546
    iput-object v5, v0, Lgn/g;->u:Landroid/graphics/Canvas;

    .line 547
    .line 548
    goto :goto_4

    .line 549
    :cond_11
    iget-object v5, v0, Lgn/g;->t:Landroid/graphics/Canvas;

    .line 550
    .line 551
    if-eqz v5, :cond_18

    .line 552
    .line 553
    iget-object v11, v0, Lgn/g;->u:Landroid/graphics/Canvas;

    .line 554
    .line 555
    if-eqz v11, :cond_18

    .line 556
    .line 557
    iget-object v11, v0, Lgn/g;->o:Ldn/i;

    .line 558
    .line 559
    if-eqz v11, :cond_18

    .line 560
    .line 561
    iget-object v12, v0, Lgn/g;->i:Landroid/graphics/Rect;

    .line 562
    .line 563
    invoke-virtual {v5, v12, v11}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/Rect;Landroid/graphics/Paint;)V

    .line 564
    .line 565
    .line 566
    iget-object v5, v0, Lgn/g;->u:Landroid/graphics/Canvas;

    .line 567
    .line 568
    iget-object v11, v0, Lgn/g;->i:Landroid/graphics/Rect;

    .line 569
    .line 570
    iget-object v12, v0, Lgn/g;->o:Ldn/i;

    .line 571
    .line 572
    invoke-virtual {v5, v11, v12}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/Rect;Landroid/graphics/Paint;)V

    .line 573
    .line 574
    .line 575
    :goto_4
    iget-object v5, v0, Lgn/g;->s:Landroid/graphics/Bitmap;

    .line 576
    .line 577
    if-eqz v5, :cond_17

    .line 578
    .line 579
    iget-object v5, v0, Lgn/g;->v:Ldn/i;

    .line 580
    .line 581
    if-nez v5, :cond_12

    .line 582
    .line 583
    new-instance v5, Ldn/i;

    .line 584
    .line 585
    const/4 v11, 0x2

    .line 586
    invoke-direct {v5, v3, v11}, Ldn/i;-><init>(II)V

    .line 587
    .line 588
    .line 589
    iput-object v5, v0, Lgn/g;->v:Ldn/i;

    .line 590
    .line 591
    :cond_12
    iget-object v5, v0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 592
    .line 593
    iget v11, v5, Landroid/graphics/RectF;->left:F

    .line 594
    .line 595
    iget v12, v10, Landroid/graphics/RectF;->left:F

    .line 596
    .line 597
    sub-float/2addr v11, v12

    .line 598
    iget v5, v5, Landroid/graphics/RectF;->top:F

    .line 599
    .line 600
    iget v10, v10, Landroid/graphics/RectF;->top:F

    .line 601
    .line 602
    sub-float/2addr v5, v10

    .line 603
    iget-object v10, v0, Lgn/g;->u:Landroid/graphics/Canvas;

    .line 604
    .line 605
    iget-object v12, v0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 606
    .line 607
    mul-float/2addr v11, v6

    .line 608
    invoke-static {v11}, Ljava/lang/Math;->round(F)I

    .line 609
    .line 610
    .line 611
    move-result v11

    .line 612
    int-to-float v11, v11

    .line 613
    mul-float/2addr v5, v8

    .line 614
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 615
    .line 616
    .line 617
    move-result v5

    .line 618
    int-to-float v5, v5

    .line 619
    invoke-virtual {v10, v12, v11, v5, v2}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;FFLandroid/graphics/Paint;)V

    .line 620
    .line 621
    .line 622
    iget-object v5, v0, Lgn/g;->w:Landroid/graphics/BlurMaskFilter;

    .line 623
    .line 624
    if-eqz v5, :cond_13

    .line 625
    .line 626
    iget v5, v0, Lgn/g;->x:F

    .line 627
    .line 628
    iget v10, v4, Lgn/a;->a:F

    .line 629
    .line 630
    cmpl-float v5, v5, v10

    .line 631
    .line 632
    if-eqz v5, :cond_15

    .line 633
    .line 634
    :cond_13
    iget v5, v4, Lgn/a;->a:F

    .line 635
    .line 636
    add-float v10, v6, v8

    .line 637
    .line 638
    mul-float/2addr v10, v5

    .line 639
    div-float v10, v10, v17

    .line 640
    .line 641
    cmpl-float v5, v10, v16

    .line 642
    .line 643
    if-lez v5, :cond_14

    .line 644
    .line 645
    new-instance v5, Landroid/graphics/BlurMaskFilter;

    .line 646
    .line 647
    sget-object v11, Landroid/graphics/BlurMaskFilter$Blur;->NORMAL:Landroid/graphics/BlurMaskFilter$Blur;

    .line 648
    .line 649
    invoke-direct {v5, v10, v11}, Landroid/graphics/BlurMaskFilter;-><init>(FLandroid/graphics/BlurMaskFilter$Blur;)V

    .line 650
    .line 651
    .line 652
    iput-object v5, v0, Lgn/g;->w:Landroid/graphics/BlurMaskFilter;

    .line 653
    .line 654
    goto :goto_5

    .line 655
    :cond_14
    iput-object v2, v0, Lgn/g;->w:Landroid/graphics/BlurMaskFilter;

    .line 656
    .line 657
    :goto_5
    iget v5, v4, Lgn/a;->a:F

    .line 658
    .line 659
    iput v5, v0, Lgn/g;->x:F

    .line 660
    .line 661
    :cond_15
    iget-object v5, v0, Lgn/g;->v:Ldn/i;

    .line 662
    .line 663
    iget v10, v4, Lgn/a;->d:I

    .line 664
    .line 665
    invoke-virtual {v5, v10}, Landroid/graphics/Paint;->setColor(I)V

    .line 666
    .line 667
    .line 668
    iget v5, v4, Lgn/a;->a:F

    .line 669
    .line 670
    cmpl-float v5, v5, v16

    .line 671
    .line 672
    if-lez v5, :cond_16

    .line 673
    .line 674
    iget-object v5, v0, Lgn/g;->v:Ldn/i;

    .line 675
    .line 676
    iget-object v10, v0, Lgn/g;->w:Landroid/graphics/BlurMaskFilter;

    .line 677
    .line 678
    invoke-virtual {v5, v10}, Landroid/graphics/Paint;->setMaskFilter(Landroid/graphics/MaskFilter;)Landroid/graphics/MaskFilter;

    .line 679
    .line 680
    .line 681
    goto :goto_6

    .line 682
    :cond_16
    iget-object v5, v0, Lgn/g;->v:Ldn/i;

    .line 683
    .line 684
    invoke-virtual {v5, v2}, Landroid/graphics/Paint;->setMaskFilter(Landroid/graphics/MaskFilter;)Landroid/graphics/MaskFilter;

    .line 685
    .line 686
    .line 687
    :goto_6
    iget-object v5, v0, Lgn/g;->v:Ldn/i;

    .line 688
    .line 689
    invoke-virtual {v5, v3}, Landroid/graphics/Paint;->setFilterBitmap(Z)V

    .line 690
    .line 691
    .line 692
    iget-object v3, v0, Lgn/g;->t:Landroid/graphics/Canvas;

    .line 693
    .line 694
    iget-object v5, v0, Lgn/g;->s:Landroid/graphics/Bitmap;

    .line 695
    .line 696
    iget v10, v4, Lgn/a;->b:F

    .line 697
    .line 698
    mul-float/2addr v10, v6

    .line 699
    invoke-static {v10}, Ljava/lang/Math;->round(F)I

    .line 700
    .line 701
    .line 702
    move-result v6

    .line 703
    int-to-float v6, v6

    .line 704
    iget v4, v4, Lgn/a;->c:F

    .line 705
    .line 706
    mul-float/2addr v4, v8

    .line 707
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 708
    .line 709
    .line 710
    move-result v4

    .line 711
    int-to-float v4, v4

    .line 712
    iget-object v8, v0, Lgn/g;->v:Ldn/i;

    .line 713
    .line 714
    invoke-virtual {v3, v5, v6, v4, v8}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;FFLandroid/graphics/Paint;)V

    .line 715
    .line 716
    .line 717
    iget-object v3, v0, Lgn/g;->r:Landroid/graphics/Bitmap;

    .line 718
    .line 719
    iget-object v4, v0, Lgn/g;->i:Landroid/graphics/Rect;

    .line 720
    .line 721
    iget-object v5, v0, Lgn/g;->f:Landroid/graphics/Rect;

    .line 722
    .line 723
    iget-object v6, v0, Lgn/g;->k:Ldn/i;

    .line 724
    .line 725
    invoke-virtual {v1, v3, v4, v5, v6}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Paint;)V

    .line 726
    .line 727
    .line 728
    goto :goto_7

    .line 729
    :cond_17
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 730
    .line 731
    const-string v1, "Expected to have allocated a shadow mask bitmap"

    .line 732
    .line 733
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 734
    .line 735
    .line 736
    throw v0

    .line 737
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 738
    .line 739
    const-string v1, "If needNewBitmap() returns true, we should have a canvas and bitmap ready"

    .line 740
    .line 741
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 742
    .line 743
    .line 744
    throw v0

    .line 745
    :cond_19
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 746
    .line 747
    const-string v1, "Cannot render to bitmap outside a start()/finish() block"

    .line 748
    .line 749
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 750
    .line 751
    .line 752
    throw v0

    .line 753
    :cond_1a
    :goto_7
    iget-object v1, v0, Lgn/g;->n:Landroid/graphics/Rect;

    .line 754
    .line 755
    if-nez v1, :cond_1b

    .line 756
    .line 757
    new-instance v1, Landroid/graphics/Rect;

    .line 758
    .line 759
    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 760
    .line 761
    .line 762
    iput-object v1, v0, Lgn/g;->n:Landroid/graphics/Rect;

    .line 763
    .line 764
    :cond_1b
    iget-object v1, v0, Lgn/g;->n:Landroid/graphics/Rect;

    .line 765
    .line 766
    iget-object v3, v0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 767
    .line 768
    invoke-virtual {v3}, Landroid/graphics/RectF;->width()F

    .line 769
    .line 770
    .line 771
    move-result v3

    .line 772
    iget-object v4, v0, Lgn/g;->q:[F

    .line 773
    .line 774
    aget v4, v4, v9

    .line 775
    .line 776
    mul-float/2addr v3, v4

    .line 777
    float-to-int v3, v3

    .line 778
    iget-object v4, v0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 779
    .line 780
    invoke-virtual {v4}, Landroid/graphics/RectF;->height()F

    .line 781
    .line 782
    .line 783
    move-result v4

    .line 784
    iget-object v5, v0, Lgn/g;->q:[F

    .line 785
    .line 786
    aget v5, v5, v7

    .line 787
    .line 788
    mul-float/2addr v4, v5

    .line 789
    float-to-int v4, v4

    .line 790
    invoke-virtual {v1, v9, v9, v3, v4}, Landroid/graphics/Rect;->set(IIII)V

    .line 791
    .line 792
    .line 793
    iget-object v1, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 794
    .line 795
    iget-object v3, v0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 796
    .line 797
    iget-object v4, v0, Lgn/g;->n:Landroid/graphics/Rect;

    .line 798
    .line 799
    iget-object v5, v0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 800
    .line 801
    iget-object v6, v0, Lgn/g;->k:Ldn/i;

    .line 802
    .line 803
    invoke-virtual {v1, v3, v4, v5, v6}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Rect;Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    .line 804
    .line 805
    .line 806
    goto :goto_8

    .line 807
    :cond_1c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 808
    .line 809
    const-string v1, "Bitmap is not ready; should\'ve been initialized at start() time"

    .line 810
    .line 811
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 812
    .line 813
    .line 814
    throw v0

    .line 815
    :cond_1d
    iget-object v1, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 816
    .line 817
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 818
    .line 819
    .line 820
    goto :goto_8

    .line 821
    :cond_1e
    iget-object v1, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 822
    .line 823
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 824
    .line 825
    .line 826
    :goto_8
    iput-object v2, v0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 827
    .line 828
    return-void

    .line 829
    :cond_1f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 830
    .line 831
    const-string v1, "OffscreenBitmap: finish() call without matching start()"

    .line 832
    .line 833
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 834
    .line 835
    .line 836
    throw v0
.end method

.method public final e(Landroid/graphics/Canvas;Landroid/graphics/RectF;Lb11/a;)Landroid/graphics/Canvas;
    .locals 10

    .line 1
    iget-object v0, p0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 2
    .line 3
    if-nez v0, :cond_16

    .line 4
    .line 5
    iget-object v0, p0, Lgn/g;->q:[F

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/16 v0, 0x9

    .line 10
    .line 11
    new-array v0, v0, [F

    .line 12
    .line 13
    iput-object v0, p0, Lgn/g;->q:[F

    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lgn/g;->p:Landroid/graphics/Matrix;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    new-instance v0, Landroid/graphics/Matrix;

    .line 20
    .line 21
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lgn/g;->p:Landroid/graphics/Matrix;

    .line 25
    .line 26
    :cond_1
    iget-object v0, p0, Lgn/g;->p:Landroid/graphics/Matrix;

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Landroid/graphics/Canvas;->getMatrix(Landroid/graphics/Matrix;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lgn/g;->p:Landroid/graphics/Matrix;

    .line 32
    .line 33
    iget-object v1, p0, Lgn/g;->q:[F

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Landroid/graphics/Matrix;->getValues([F)V

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, Lgn/g;->q:[F

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    aget v1, v0, v1

    .line 42
    .line 43
    const/4 v2, 0x4

    .line 44
    aget v0, v0, v2

    .line 45
    .line 46
    iget-object v3, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 47
    .line 48
    if-nez v3, :cond_2

    .line 49
    .line 50
    new-instance v3, Landroid/graphics/RectF;

    .line 51
    .line 52
    invoke-direct {v3}, Landroid/graphics/RectF;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v3, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 56
    .line 57
    :cond_2
    iget-object v3, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 58
    .line 59
    iget v4, p2, Landroid/graphics/RectF;->left:F

    .line 60
    .line 61
    mul-float/2addr v4, v1

    .line 62
    iget v5, p2, Landroid/graphics/RectF;->top:F

    .line 63
    .line 64
    mul-float/2addr v5, v0

    .line 65
    iget v6, p2, Landroid/graphics/RectF;->right:F

    .line 66
    .line 67
    mul-float/2addr v6, v1

    .line 68
    iget v7, p2, Landroid/graphics/RectF;->bottom:F

    .line 69
    .line 70
    mul-float/2addr v7, v0

    .line 71
    invoke-virtual {v3, v4, v5, v6, v7}, Landroid/graphics/RectF;->set(FFFF)V

    .line 72
    .line 73
    .line 74
    iput-object p1, p0, Lgn/g;->a:Landroid/graphics/Canvas;

    .line 75
    .line 76
    iput-object p3, p0, Lgn/g;->b:Lb11/a;

    .line 77
    .line 78
    iget v3, p3, Lb11/a;->e:I

    .line 79
    .line 80
    const/16 v4, 0xff

    .line 81
    .line 82
    const/4 v5, 0x2

    .line 83
    const/4 v6, 0x3

    .line 84
    const/4 v7, 0x1

    .line 85
    if-ge v3, v4, :cond_3

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_3
    invoke-virtual {p3}, Lb11/a;->c()Z

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    if-nez v3, :cond_4

    .line 93
    .line 94
    move v2, v7

    .line 95
    goto :goto_2

    .line 96
    :cond_4
    :goto_0
    invoke-virtual {p3}, Lb11/a;->c()Z

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    if-nez v3, :cond_5

    .line 101
    .line 102
    move v2, v5

    .line 103
    goto :goto_2

    .line 104
    :cond_5
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 105
    .line 106
    invoke-virtual {p1}, Landroid/graphics/Canvas;->isHardwareAccelerated()Z

    .line 107
    .line 108
    .line 109
    move-result v4

    .line 110
    if-nez v4, :cond_6

    .line 111
    .line 112
    :goto_1
    move v2, v6

    .line 113
    goto :goto_2

    .line 114
    :cond_6
    const/16 v4, 0x1f

    .line 115
    .line 116
    if-gt v3, v4, :cond_7

    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_7
    :goto_2
    iput v2, p0, Lgn/g;->c:I

    .line 120
    .line 121
    iget-object v2, p0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 122
    .line 123
    if-nez v2, :cond_8

    .line 124
    .line 125
    new-instance v2, Landroid/graphics/RectF;

    .line 126
    .line 127
    invoke-direct {v2}, Landroid/graphics/RectF;-><init>()V

    .line 128
    .line 129
    .line 130
    iput-object v2, p0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 131
    .line 132
    :cond_8
    iget-object v2, p0, Lgn/g;->d:Landroid/graphics/RectF;

    .line 133
    .line 134
    iget v3, p2, Landroid/graphics/RectF;->left:F

    .line 135
    .line 136
    float-to-int v3, v3

    .line 137
    int-to-float v3, v3

    .line 138
    iget v4, p2, Landroid/graphics/RectF;->top:F

    .line 139
    .line 140
    float-to-int v4, v4

    .line 141
    int-to-float v4, v4

    .line 142
    iget v8, p2, Landroid/graphics/RectF;->right:F

    .line 143
    .line 144
    float-to-int v8, v8

    .line 145
    int-to-float v8, v8

    .line 146
    iget v9, p2, Landroid/graphics/RectF;->bottom:F

    .line 147
    .line 148
    float-to-int v9, v9

    .line 149
    int-to-float v9, v9

    .line 150
    invoke-virtual {v2, v3, v4, v8, v9}, Landroid/graphics/RectF;->set(FFFF)V

    .line 151
    .line 152
    .line 153
    iget-object v2, p0, Lgn/g;->k:Ldn/i;

    .line 154
    .line 155
    if-nez v2, :cond_9

    .line 156
    .line 157
    new-instance v2, Ldn/i;

    .line 158
    .line 159
    invoke-direct {v2}, Ldn/i;-><init>()V

    .line 160
    .line 161
    .line 162
    iput-object v2, p0, Lgn/g;->k:Ldn/i;

    .line 163
    .line 164
    :cond_9
    iget-object v2, p0, Lgn/g;->k:Ldn/i;

    .line 165
    .line 166
    invoke-virtual {v2}, Landroid/graphics/Paint;->reset()V

    .line 167
    .line 168
    .line 169
    iget v2, p0, Lgn/g;->c:I

    .line 170
    .line 171
    invoke-static {v2}, Lu/w;->o(I)I

    .line 172
    .line 173
    .line 174
    move-result v2

    .line 175
    if-eqz v2, :cond_15

    .line 176
    .line 177
    const/4 v3, 0x0

    .line 178
    if-eq v2, v7, :cond_14

    .line 179
    .line 180
    sget-object p1, Lgn/g;->B:Landroid/graphics/Matrix;

    .line 181
    .line 182
    if-eq v2, v5, :cond_f

    .line 183
    .line 184
    if-ne v2, v6, :cond_e

    .line 185
    .line 186
    iget-object v2, p0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 187
    .line 188
    if-nez v2, :cond_a

    .line 189
    .line 190
    new-instance v2, Landroid/graphics/RenderNode;

    .line 191
    .line 192
    const-string v4, "OffscreenLayer.main"

    .line 193
    .line 194
    invoke-direct {v2, v4}, Landroid/graphics/RenderNode;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    iput-object v2, p0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 198
    .line 199
    :cond_a
    invoke-virtual {p3}, Lb11/a;->c()Z

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    if-eqz v2, :cond_b

    .line 204
    .line 205
    iget-object v2, p0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 206
    .line 207
    if-nez v2, :cond_b

    .line 208
    .line 209
    new-instance v2, Landroid/graphics/RenderNode;

    .line 210
    .line 211
    const-string v4, "OffscreenLayer.shadow"

    .line 212
    .line 213
    invoke-direct {v2, v4}, Landroid/graphics/RenderNode;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    iput-object v2, p0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 217
    .line 218
    iput-object v3, p0, Lgn/g;->A:Lgn/a;

    .line 219
    .line 220
    :cond_b
    iget-object v2, p0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 221
    .line 222
    iget v3, p3, Lb11/a;->e:I

    .line 223
    .line 224
    int-to-float v3, v3

    .line 225
    const/high16 v4, 0x437f0000    # 255.0f

    .line 226
    .line 227
    div-float/2addr v3, v4

    .line 228
    invoke-virtual {v2, v3}, Landroid/graphics/RenderNode;->setAlpha(F)Z

    .line 229
    .line 230
    .line 231
    invoke-virtual {p3}, Lb11/a;->c()Z

    .line 232
    .line 233
    .line 234
    move-result v2

    .line 235
    if-eqz v2, :cond_d

    .line 236
    .line 237
    iget-object v2, p0, Lgn/g;->z:Landroid/graphics/RenderNode;

    .line 238
    .line 239
    if-eqz v2, :cond_c

    .line 240
    .line 241
    iget p3, p3, Lb11/a;->e:I

    .line 242
    .line 243
    int-to-float p3, p3

    .line 244
    div-float/2addr p3, v4

    .line 245
    invoke-virtual {v2, p3}, Landroid/graphics/RenderNode;->setAlpha(F)Z

    .line 246
    .line 247
    .line 248
    goto :goto_3

    .line 249
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 250
    .line 251
    const-string p1, "Must initialize shadowRenderNode when we have shadow"

    .line 252
    .line 253
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    throw p0

    .line 257
    :cond_d
    :goto_3
    iget-object p3, p0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 258
    .line 259
    invoke-virtual {p3, v7}, Landroid/graphics/RenderNode;->setHasOverlappingRendering(Z)Z

    .line 260
    .line 261
    .line 262
    iget-object p3, p0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 263
    .line 264
    iget-object v2, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 265
    .line 266
    iget v3, v2, Landroid/graphics/RectF;->left:F

    .line 267
    .line 268
    float-to-int v3, v3

    .line 269
    iget v4, v2, Landroid/graphics/RectF;->top:F

    .line 270
    .line 271
    float-to-int v4, v4

    .line 272
    iget v5, v2, Landroid/graphics/RectF;->right:F

    .line 273
    .line 274
    float-to-int v5, v5

    .line 275
    iget v2, v2, Landroid/graphics/RectF;->bottom:F

    .line 276
    .line 277
    float-to-int v2, v2

    .line 278
    invoke-virtual {p3, v3, v4, v5, v2}, Landroid/graphics/RenderNode;->setPosition(IIII)Z

    .line 279
    .line 280
    .line 281
    iget-object p3, p0, Lgn/g;->y:Landroid/graphics/RenderNode;

    .line 282
    .line 283
    iget-object v2, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 284
    .line 285
    invoke-virtual {v2}, Landroid/graphics/RectF;->width()F

    .line 286
    .line 287
    .line 288
    move-result v2

    .line 289
    float-to-int v2, v2

    .line 290
    iget-object p0, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 291
    .line 292
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 293
    .line 294
    .line 295
    move-result p0

    .line 296
    float-to-int p0, p0

    .line 297
    invoke-virtual {p3, v2, p0}, Landroid/graphics/RenderNode;->beginRecording(II)Landroid/graphics/RecordingCanvas;

    .line 298
    .line 299
    .line 300
    move-result-object p0

    .line 301
    invoke-virtual {p0, p1}, Landroid/graphics/Canvas;->setMatrix(Landroid/graphics/Matrix;)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {p0, v1, v0}, Landroid/graphics/Canvas;->scale(FF)V

    .line 305
    .line 306
    .line 307
    iget p1, p2, Landroid/graphics/RectF;->left:F

    .line 308
    .line 309
    neg-float p1, p1

    .line 310
    iget p2, p2, Landroid/graphics/RectF;->top:F

    .line 311
    .line 312
    neg-float p2, p2

    .line 313
    invoke-virtual {p0, p1, p2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 314
    .line 315
    .line 316
    return-object p0

    .line 317
    :cond_e
    new-instance p0, Ljava/lang/RuntimeException;

    .line 318
    .line 319
    const-string p1, "Invalid render strategy for OffscreenLayer"

    .line 320
    .line 321
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 322
    .line 323
    .line 324
    throw p0

    .line 325
    :cond_f
    iget-object v2, p0, Lgn/g;->o:Ldn/i;

    .line 326
    .line 327
    if-nez v2, :cond_10

    .line 328
    .line 329
    new-instance v2, Ldn/i;

    .line 330
    .line 331
    invoke-direct {v2}, Ldn/i;-><init>()V

    .line 332
    .line 333
    .line 334
    iput-object v2, p0, Lgn/g;->o:Ldn/i;

    .line 335
    .line 336
    new-instance v4, Landroid/graphics/PorterDuffXfermode;

    .line 337
    .line 338
    sget-object v5, Landroid/graphics/PorterDuff$Mode;->CLEAR:Landroid/graphics/PorterDuff$Mode;

    .line 339
    .line 340
    invoke-direct {v4, v5}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {v2, v4}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 344
    .line 345
    .line 346
    :cond_10
    iget-object v2, p0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 347
    .line 348
    iget-object v4, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 349
    .line 350
    invoke-static {v2, v4}, Lgn/g;->d(Landroid/graphics/Bitmap;Landroid/graphics/RectF;)Z

    .line 351
    .line 352
    .line 353
    move-result v2

    .line 354
    if-eqz v2, :cond_12

    .line 355
    .line 356
    iget-object p1, p0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 357
    .line 358
    if-eqz p1, :cond_11

    .line 359
    .line 360
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->recycle()V

    .line 361
    .line 362
    .line 363
    :cond_11
    iget-object p1, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 364
    .line 365
    sget-object v2, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 366
    .line 367
    invoke-static {p1, v2}, Lgn/g;->a(Landroid/graphics/RectF;Landroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 368
    .line 369
    .line 370
    move-result-object p1

    .line 371
    iput-object p1, p0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 372
    .line 373
    new-instance p1, Landroid/graphics/Canvas;

    .line 374
    .line 375
    iget-object v2, p0, Lgn/g;->l:Landroid/graphics/Bitmap;

    .line 376
    .line 377
    invoke-direct {p1, v2}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 378
    .line 379
    .line 380
    iput-object p1, p0, Lgn/g;->m:Landroid/graphics/Canvas;

    .line 381
    .line 382
    goto :goto_4

    .line 383
    :cond_12
    iget-object v2, p0, Lgn/g;->m:Landroid/graphics/Canvas;

    .line 384
    .line 385
    if-eqz v2, :cond_13

    .line 386
    .line 387
    invoke-virtual {v2, p1}, Landroid/graphics/Canvas;->setMatrix(Landroid/graphics/Matrix;)V

    .line 388
    .line 389
    .line 390
    iget-object v4, p0, Lgn/g;->m:Landroid/graphics/Canvas;

    .line 391
    .line 392
    iget-object p1, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 393
    .line 394
    invoke-virtual {p1}, Landroid/graphics/RectF;->width()F

    .line 395
    .line 396
    .line 397
    move-result p1

    .line 398
    const/high16 v2, 0x3f800000    # 1.0f

    .line 399
    .line 400
    add-float v7, p1, v2

    .line 401
    .line 402
    iget-object p1, p0, Lgn/g;->j:Landroid/graphics/RectF;

    .line 403
    .line 404
    invoke-virtual {p1}, Landroid/graphics/RectF;->height()F

    .line 405
    .line 406
    .line 407
    move-result p1

    .line 408
    add-float v8, p1, v2

    .line 409
    .line 410
    iget-object v9, p0, Lgn/g;->o:Ldn/i;

    .line 411
    .line 412
    const/high16 v5, -0x40800000    # -1.0f

    .line 413
    .line 414
    const/high16 v6, -0x40800000    # -1.0f

    .line 415
    .line 416
    invoke-virtual/range {v4 .. v9}, Landroid/graphics/Canvas;->drawRect(FFFFLandroid/graphics/Paint;)V

    .line 417
    .line 418
    .line 419
    :goto_4
    iget-object p1, p0, Lgn/g;->k:Ldn/i;

    .line 420
    .line 421
    sget v2, Ls5/c;->a:I

    .line 422
    .line 423
    invoke-virtual {p1, v3}, Landroid/graphics/Paint;->setBlendMode(Landroid/graphics/BlendMode;)V

    .line 424
    .line 425
    .line 426
    iget-object p1, p0, Lgn/g;->k:Ldn/i;

    .line 427
    .line 428
    invoke-virtual {p1, v3}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 429
    .line 430
    .line 431
    iget-object p1, p0, Lgn/g;->k:Ldn/i;

    .line 432
    .line 433
    iget p3, p3, Lb11/a;->e:I

    .line 434
    .line 435
    invoke-virtual {p1, p3}, Ldn/i;->setAlpha(I)V

    .line 436
    .line 437
    .line 438
    iget-object p0, p0, Lgn/g;->m:Landroid/graphics/Canvas;

    .line 439
    .line 440
    invoke-virtual {p0, v1, v0}, Landroid/graphics/Canvas;->scale(FF)V

    .line 441
    .line 442
    .line 443
    iget p1, p2, Landroid/graphics/RectF;->left:F

    .line 444
    .line 445
    neg-float p1, p1

    .line 446
    iget p2, p2, Landroid/graphics/RectF;->top:F

    .line 447
    .line 448
    neg-float p2, p2

    .line 449
    invoke-virtual {p0, p1, p2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 450
    .line 451
    .line 452
    return-object p0

    .line 453
    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 454
    .line 455
    const-string p1, "If needNewBitmap() returns true, we should have a canvas ready"

    .line 456
    .line 457
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 458
    .line 459
    .line 460
    throw p0

    .line 461
    :cond_14
    iget-object v0, p0, Lgn/g;->k:Ldn/i;

    .line 462
    .line 463
    iget p3, p3, Lb11/a;->e:I

    .line 464
    .line 465
    invoke-virtual {v0, p3}, Ldn/i;->setAlpha(I)V

    .line 466
    .line 467
    .line 468
    iget-object p3, p0, Lgn/g;->k:Ldn/i;

    .line 469
    .line 470
    invoke-virtual {p3, v3}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 471
    .line 472
    .line 473
    iget-object p0, p0, Lgn/g;->k:Ldn/i;

    .line 474
    .line 475
    sget-object p3, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 476
    .line 477
    invoke-virtual {p1, p2, p0}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 478
    .line 479
    .line 480
    return-object p1

    .line 481
    :cond_15
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 482
    .line 483
    .line 484
    return-object p1

    .line 485
    :cond_16
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 486
    .line 487
    const-string p1, "Cannot nest start() calls on a single OffscreenBitmap - call finish() first"

    .line 488
    .line 489
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 490
    .line 491
    .line 492
    throw p0
.end method

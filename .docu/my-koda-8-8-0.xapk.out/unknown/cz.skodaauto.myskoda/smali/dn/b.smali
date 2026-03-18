.class public abstract Ldn/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwm/e;
.implements Lxm/a;


# instance fields
.field public final a:Landroid/graphics/Path;

.field public final b:Landroid/graphics/Matrix;

.field public final c:Landroid/graphics/Matrix;

.field public final d:Ldn/i;

.field public final e:Ldn/i;

.field public final f:Ldn/i;

.field public final g:Ldn/i;

.field public final h:Ldn/i;

.field public final i:Landroid/graphics/RectF;

.field public final j:Landroid/graphics/RectF;

.field public final k:Landroid/graphics/RectF;

.field public final l:Landroid/graphics/RectF;

.field public final m:Landroid/graphics/RectF;

.field public final n:Landroid/graphics/Matrix;

.field public final o:Lum/j;

.field public final p:Ldn/e;

.field public final q:Lrn/i;

.field public final r:Lxm/f;

.field public s:Ldn/b;

.field public t:Ldn/b;

.field public u:Ljava/util/List;

.field public final v:Ljava/util/ArrayList;

.field public final w:Lxm/n;

.field public x:Z

.field public y:F

.field public z:Landroid/graphics/BlurMaskFilter;


# direct methods
.method public constructor <init>(Lum/j;Ldn/e;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Path;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ldn/b;->a:Landroid/graphics/Path;

    .line 10
    .line 11
    new-instance v0, Landroid/graphics/Matrix;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ldn/b;->b:Landroid/graphics/Matrix;

    .line 17
    .line 18
    new-instance v0, Landroid/graphics/Matrix;

    .line 19
    .line 20
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Ldn/b;->c:Landroid/graphics/Matrix;

    .line 24
    .line 25
    new-instance v0, Ldn/i;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    const/4 v2, 0x1

    .line 29
    invoke-direct {v0, v2, v1}, Ldn/i;-><init>(II)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Ldn/b;->d:Ldn/i;

    .line 33
    .line 34
    new-instance v0, Ldn/i;

    .line 35
    .line 36
    sget-object v1, Landroid/graphics/PorterDuff$Mode;->DST_IN:Landroid/graphics/PorterDuff$Mode;

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ldn/i;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 39
    .line 40
    .line 41
    iput-object v0, p0, Ldn/b;->e:Ldn/i;

    .line 42
    .line 43
    new-instance v0, Ldn/i;

    .line 44
    .line 45
    sget-object v3, Landroid/graphics/PorterDuff$Mode;->DST_OUT:Landroid/graphics/PorterDuff$Mode;

    .line 46
    .line 47
    invoke-direct {v0, v3}, Ldn/i;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 48
    .line 49
    .line 50
    iput-object v0, p0, Ldn/b;->f:Ldn/i;

    .line 51
    .line 52
    new-instance v0, Ldn/i;

    .line 53
    .line 54
    const/4 v4, 0x2

    .line 55
    invoke-direct {v0, v2, v4}, Ldn/i;-><init>(II)V

    .line 56
    .line 57
    .line 58
    iput-object v0, p0, Ldn/b;->g:Ldn/i;

    .line 59
    .line 60
    new-instance v4, Ldn/i;

    .line 61
    .line 62
    sget-object v5, Landroid/graphics/PorterDuff$Mode;->CLEAR:Landroid/graphics/PorterDuff$Mode;

    .line 63
    .line 64
    invoke-direct {v4}, Ldn/i;-><init>()V

    .line 65
    .line 66
    .line 67
    new-instance v6, Landroid/graphics/PorterDuffXfermode;

    .line 68
    .line 69
    invoke-direct {v6, v5}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v4, v6}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 73
    .line 74
    .line 75
    iput-object v4, p0, Ldn/b;->h:Ldn/i;

    .line 76
    .line 77
    new-instance v4, Landroid/graphics/RectF;

    .line 78
    .line 79
    invoke-direct {v4}, Landroid/graphics/RectF;-><init>()V

    .line 80
    .line 81
    .line 82
    iput-object v4, p0, Ldn/b;->i:Landroid/graphics/RectF;

    .line 83
    .line 84
    new-instance v4, Landroid/graphics/RectF;

    .line 85
    .line 86
    invoke-direct {v4}, Landroid/graphics/RectF;-><init>()V

    .line 87
    .line 88
    .line 89
    iput-object v4, p0, Ldn/b;->j:Landroid/graphics/RectF;

    .line 90
    .line 91
    new-instance v4, Landroid/graphics/RectF;

    .line 92
    .line 93
    invoke-direct {v4}, Landroid/graphics/RectF;-><init>()V

    .line 94
    .line 95
    .line 96
    iput-object v4, p0, Ldn/b;->k:Landroid/graphics/RectF;

    .line 97
    .line 98
    new-instance v4, Landroid/graphics/RectF;

    .line 99
    .line 100
    invoke-direct {v4}, Landroid/graphics/RectF;-><init>()V

    .line 101
    .line 102
    .line 103
    iput-object v4, p0, Ldn/b;->l:Landroid/graphics/RectF;

    .line 104
    .line 105
    new-instance v4, Landroid/graphics/RectF;

    .line 106
    .line 107
    invoke-direct {v4}, Landroid/graphics/RectF;-><init>()V

    .line 108
    .line 109
    .line 110
    iput-object v4, p0, Ldn/b;->m:Landroid/graphics/RectF;

    .line 111
    .line 112
    new-instance v4, Landroid/graphics/Matrix;

    .line 113
    .line 114
    invoke-direct {v4}, Landroid/graphics/Matrix;-><init>()V

    .line 115
    .line 116
    .line 117
    iput-object v4, p0, Ldn/b;->n:Landroid/graphics/Matrix;

    .line 118
    .line 119
    new-instance v4, Ljava/util/ArrayList;

    .line 120
    .line 121
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 122
    .line 123
    .line 124
    iput-object v4, p0, Ldn/b;->v:Ljava/util/ArrayList;

    .line 125
    .line 126
    iput-boolean v2, p0, Ldn/b;->x:Z

    .line 127
    .line 128
    const/4 v4, 0x0

    .line 129
    iput v4, p0, Ldn/b;->y:F

    .line 130
    .line 131
    iput-object p1, p0, Ldn/b;->o:Lum/j;

    .line 132
    .line 133
    iput-object p2, p0, Ldn/b;->p:Ldn/e;

    .line 134
    .line 135
    iget-object p1, p2, Ldn/e;->h:Ljava/util/List;

    .line 136
    .line 137
    iget v4, p2, Ldn/e;->u:I

    .line 138
    .line 139
    const/4 v5, 0x3

    .line 140
    if-ne v4, v5, :cond_0

    .line 141
    .line 142
    new-instance v1, Landroid/graphics/PorterDuffXfermode;

    .line 143
    .line 144
    invoke-direct {v1, v3}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 148
    .line 149
    .line 150
    goto :goto_0

    .line 151
    :cond_0
    new-instance v3, Landroid/graphics/PorterDuffXfermode;

    .line 152
    .line 153
    invoke-direct {v3, v1}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0, v3}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 157
    .line 158
    .line 159
    :goto_0
    iget-object p2, p2, Ldn/e;->i:Lbn/e;

    .line 160
    .line 161
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 162
    .line 163
    .line 164
    new-instance v0, Lxm/n;

    .line 165
    .line 166
    invoke-direct {v0, p2}, Lxm/n;-><init>(Lbn/e;)V

    .line 167
    .line 168
    .line 169
    iput-object v0, p0, Ldn/b;->w:Lxm/n;

    .line 170
    .line 171
    invoke-virtual {v0, p0}, Lxm/n;->b(Lxm/a;)V

    .line 172
    .line 173
    .line 174
    if-eqz p1, :cond_2

    .line 175
    .line 176
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 177
    .line 178
    .line 179
    move-result p2

    .line 180
    if-nez p2, :cond_2

    .line 181
    .line 182
    new-instance p2, Lrn/i;

    .line 183
    .line 184
    invoke-direct {p2, p1}, Lrn/i;-><init>(Ljava/util/List;)V

    .line 185
    .line 186
    .line 187
    iput-object p2, p0, Ldn/b;->q:Lrn/i;

    .line 188
    .line 189
    iget-object p1, p2, Lrn/i;->e:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast p1, Ljava/util/ArrayList;

    .line 192
    .line 193
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 194
    .line 195
    .line 196
    move-result-object p1

    .line 197
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 198
    .line 199
    .line 200
    move-result p2

    .line 201
    if-eqz p2, :cond_1

    .line 202
    .line 203
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p2

    .line 207
    check-cast p2, Lxm/e;

    .line 208
    .line 209
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 210
    .line 211
    .line 212
    goto :goto_1

    .line 213
    :cond_1
    iget-object p1, p0, Ldn/b;->q:Lrn/i;

    .line 214
    .line 215
    iget-object p1, p1, Lrn/i;->f:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast p1, Ljava/util/ArrayList;

    .line 218
    .line 219
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 224
    .line 225
    .line 226
    move-result p2

    .line 227
    if-eqz p2, :cond_2

    .line 228
    .line 229
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object p2

    .line 233
    check-cast p2, Lxm/e;

    .line 234
    .line 235
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 239
    .line 240
    .line 241
    goto :goto_2

    .line 242
    :cond_2
    iget-object p1, p0, Ldn/b;->p:Ldn/e;

    .line 243
    .line 244
    iget-object p2, p1, Ldn/e;->t:Ljava/util/List;

    .line 245
    .line 246
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 247
    .line 248
    .line 249
    move-result p2

    .line 250
    if-nez p2, :cond_5

    .line 251
    .line 252
    new-instance p2, Lxm/f;

    .line 253
    .line 254
    iget-object p1, p1, Ldn/e;->t:Ljava/util/List;

    .line 255
    .line 256
    const/4 v0, 0x1

    .line 257
    invoke-direct {p2, p1, v0}, Lxm/f;-><init>(Ljava/util/List;I)V

    .line 258
    .line 259
    .line 260
    iput-object p2, p0, Ldn/b;->r:Lxm/f;

    .line 261
    .line 262
    iput-boolean v2, p2, Lxm/e;->b:Z

    .line 263
    .line 264
    new-instance p1, Ldn/a;

    .line 265
    .line 266
    invoke-direct {p1, p0}, Ldn/a;-><init>(Ldn/b;)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {p2, p1}, Lxm/e;->a(Lxm/a;)V

    .line 270
    .line 271
    .line 272
    iget-object p1, p0, Ldn/b;->r:Lxm/f;

    .line 273
    .line 274
    invoke-virtual {p1}, Lxm/e;->d()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object p1

    .line 278
    check-cast p1, Ljava/lang/Float;

    .line 279
    .line 280
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 281
    .line 282
    .line 283
    move-result p1

    .line 284
    const/high16 p2, 0x3f800000    # 1.0f

    .line 285
    .line 286
    cmpl-float p1, p1, p2

    .line 287
    .line 288
    if-nez p1, :cond_3

    .line 289
    .line 290
    goto :goto_3

    .line 291
    :cond_3
    const/4 v2, 0x0

    .line 292
    :goto_3
    iget-boolean p1, p0, Ldn/b;->x:Z

    .line 293
    .line 294
    if-eq v2, p1, :cond_4

    .line 295
    .line 296
    iput-boolean v2, p0, Ldn/b;->x:Z

    .line 297
    .line 298
    iget-object p1, p0, Ldn/b;->o:Lum/j;

    .line 299
    .line 300
    invoke-virtual {p1}, Lum/j;->invalidateSelf()V

    .line 301
    .line 302
    .line 303
    :cond_4
    iget-object p1, p0, Ldn/b;->r:Lxm/f;

    .line 304
    .line 305
    invoke-virtual {p0, p1}, Ldn/b;->f(Lxm/e;)V

    .line 306
    .line 307
    .line 308
    return-void

    .line 309
    :cond_5
    iget-boolean p1, p0, Ldn/b;->x:Z

    .line 310
    .line 311
    if-eq v2, p1, :cond_6

    .line 312
    .line 313
    iput-boolean v2, p0, Ldn/b;->x:Z

    .line 314
    .line 315
    iget-object p0, p0, Ldn/b;->o:Lum/j;

    .line 316
    .line 317
    invoke-virtual {p0}, Lum/j;->invalidateSelf()V

    .line 318
    .line 319
    .line 320
    :cond_6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    iget-object p0, p0, Ldn/b;->o:Lum/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lum/j;->invalidateSelf()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b(Ljava/util/List;Ljava/util/List;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v7, p2

    .line 6
    .line 7
    move/from16 v8, p3

    .line 8
    .line 9
    move-object/from16 v9, p4

    .line 10
    .line 11
    iget-boolean v2, v0, Ldn/b;->x:Z

    .line 12
    .line 13
    if-eqz v2, :cond_28

    .line 14
    .line 15
    iget-object v2, v0, Ldn/b;->p:Ldn/e;

    .line 16
    .line 17
    iget-boolean v3, v2, Ldn/e;->v:Z

    .line 18
    .line 19
    iget v4, v2, Ldn/e;->y:I

    .line 20
    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    goto/16 :goto_15

    .line 24
    .line 25
    :cond_0
    invoke-virtual {v0}, Ldn/b;->g()V

    .line 26
    .line 27
    .line 28
    iget-object v10, v0, Ldn/b;->b:Landroid/graphics/Matrix;

    .line 29
    .line 30
    invoke-virtual {v10}, Landroid/graphics/Matrix;->reset()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v10, v7}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 34
    .line 35
    .line 36
    iget-object v3, v0, Ldn/b;->u:Ljava/util/List;

    .line 37
    .line 38
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    const/4 v11, 0x1

    .line 43
    sub-int/2addr v3, v11

    .line 44
    :goto_0
    if-ltz v3, :cond_1

    .line 45
    .line 46
    iget-object v5, v0, Ldn/b;->u:Ljava/util/List;

    .line 47
    .line 48
    invoke-interface {v5, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    check-cast v5, Ldn/b;

    .line 53
    .line 54
    iget-object v5, v5, Ldn/b;->w:Lxm/n;

    .line 55
    .line 56
    invoke-virtual {v5}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    invoke-virtual {v10, v5}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 61
    .line 62
    .line 63
    add-int/lit8 v3, v3, -0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    iget-object v3, v0, Ldn/b;->w:Lxm/n;

    .line 67
    .line 68
    iget-object v5, v3, Lxm/n;->j:Lxm/f;

    .line 69
    .line 70
    if-eqz v5, :cond_2

    .line 71
    .line 72
    invoke-virtual {v5}, Lxm/e;->d()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    check-cast v5, Ljava/lang/Integer;

    .line 77
    .line 78
    if-eqz v5, :cond_2

    .line 79
    .line 80
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    goto :goto_1

    .line 85
    :cond_2
    const/16 v5, 0x64

    .line 86
    .line 87
    :goto_1
    int-to-float v6, v8

    .line 88
    const/high16 v12, 0x437f0000    # 255.0f

    .line 89
    .line 90
    div-float/2addr v6, v12

    .line 91
    int-to-float v5, v5

    .line 92
    mul-float/2addr v6, v5

    .line 93
    const/high16 v5, 0x42c80000    # 100.0f

    .line 94
    .line 95
    div-float/2addr v6, v5

    .line 96
    mul-float/2addr v6, v12

    .line 97
    float-to-int v12, v6

    .line 98
    iget-object v5, v0, Ldn/b;->s:Ldn/b;

    .line 99
    .line 100
    if-eqz v5, :cond_3

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_3
    invoke-virtual {v0}, Ldn/b;->j()Z

    .line 104
    .line 105
    .line 106
    move-result v5

    .line 107
    if-nez v5, :cond_4

    .line 108
    .line 109
    if-ne v4, v11, :cond_4

    .line 110
    .line 111
    invoke-virtual {v3}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    invoke-virtual {v10, v2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, v1, v10, v12, v9}, Ldn/b;->h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0}, Ldn/b;->k()V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :cond_4
    :goto_2
    iget-object v13, v0, Ldn/b;->i:Landroid/graphics/RectF;

    .line 126
    .line 127
    const/4 v14, 0x0

    .line 128
    invoke-virtual {v0, v13, v10, v14}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 129
    .line 130
    .line 131
    iget-object v5, v0, Ldn/b;->s:Ldn/b;

    .line 132
    .line 133
    const/4 v15, 0x3

    .line 134
    const/4 v6, 0x0

    .line 135
    if-eqz v5, :cond_6

    .line 136
    .line 137
    iget v2, v2, Ldn/e;->u:I

    .line 138
    .line 139
    if-ne v2, v15, :cond_5

    .line 140
    .line 141
    goto :goto_3

    .line 142
    :cond_5
    iget-object v2, v0, Ldn/b;->l:Landroid/graphics/RectF;

    .line 143
    .line 144
    invoke-virtual {v2, v6, v6, v6, v6}, Landroid/graphics/RectF;->set(FFFF)V

    .line 145
    .line 146
    .line 147
    iget-object v5, v0, Ldn/b;->s:Ldn/b;

    .line 148
    .line 149
    invoke-virtual {v5, v2, v7, v11}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v13, v2}, Landroid/graphics/RectF;->intersect(Landroid/graphics/RectF;)Z

    .line 153
    .line 154
    .line 155
    move-result v2

    .line 156
    if-nez v2, :cond_6

    .line 157
    .line 158
    invoke-virtual {v13, v6, v6, v6, v6}, Landroid/graphics/RectF;->set(FFFF)V

    .line 159
    .line 160
    .line 161
    :cond_6
    :goto_3
    invoke-virtual {v3}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 162
    .line 163
    .line 164
    move-result-object v2

    .line 165
    invoke-virtual {v10, v2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 166
    .line 167
    .line 168
    iget-object v2, v0, Ldn/b;->k:Landroid/graphics/RectF;

    .line 169
    .line 170
    invoke-virtual {v2, v6, v6, v6, v6}, Landroid/graphics/RectF;->set(FFFF)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v0}, Ldn/b;->j()Z

    .line 174
    .line 175
    .line 176
    move-result v3

    .line 177
    iget-object v5, v0, Ldn/b;->q:Lrn/i;

    .line 178
    .line 179
    iget-object v6, v0, Ldn/b;->a:Landroid/graphics/Path;

    .line 180
    .line 181
    if-nez v3, :cond_9

    .line 182
    .line 183
    :cond_7
    :goto_4
    move-object/from16 v17, v5

    .line 184
    .line 185
    move-object/from16 v18, v6

    .line 186
    .line 187
    :cond_8
    const/4 v2, 0x0

    .line 188
    goto/16 :goto_9

    .line 189
    .line 190
    :cond_9
    iget-object v3, v5, Lrn/i;->g:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast v3, Ljava/util/List;

    .line 193
    .line 194
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 195
    .line 196
    .line 197
    move-result v3

    .line 198
    const/4 v15, 0x0

    .line 199
    :goto_5
    if-ge v15, v3, :cond_e

    .line 200
    .line 201
    iget-object v14, v5, Lrn/i;->g:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v14, Ljava/util/List;

    .line 204
    .line 205
    invoke-interface {v14, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v14

    .line 209
    check-cast v14, Lcn/f;

    .line 210
    .line 211
    iget-object v11, v5, Lrn/i;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast v11, Ljava/util/ArrayList;

    .line 214
    .line 215
    invoke-virtual {v11, v15}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    check-cast v11, Lxm/e;

    .line 220
    .line 221
    invoke-virtual {v11}, Lxm/e;->d()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v11

    .line 225
    check-cast v11, Landroid/graphics/Path;

    .line 226
    .line 227
    if-nez v11, :cond_a

    .line 228
    .line 229
    move/from16 v16, v3

    .line 230
    .line 231
    :goto_6
    move-object/from16 v17, v5

    .line 232
    .line 233
    move-object/from16 v18, v6

    .line 234
    .line 235
    goto :goto_8

    .line 236
    :cond_a
    invoke-virtual {v6, v11}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v6, v10}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 240
    .line 241
    .line 242
    iget v11, v14, Lcn/f;->a:I

    .line 243
    .line 244
    invoke-static {v11}, Lu/w;->o(I)I

    .line 245
    .line 246
    .line 247
    move-result v11

    .line 248
    move/from16 v16, v3

    .line 249
    .line 250
    if-eqz v11, :cond_b

    .line 251
    .line 252
    const/4 v3, 0x1

    .line 253
    if-eq v11, v3, :cond_7

    .line 254
    .line 255
    const/4 v3, 0x2

    .line 256
    if-eq v11, v3, :cond_b

    .line 257
    .line 258
    const/4 v3, 0x3

    .line 259
    if-eq v11, v3, :cond_7

    .line 260
    .line 261
    goto :goto_7

    .line 262
    :cond_b
    iget-boolean v3, v14, Lcn/f;->d:Z

    .line 263
    .line 264
    if-eqz v3, :cond_c

    .line 265
    .line 266
    goto :goto_4

    .line 267
    :cond_c
    :goto_7
    iget-object v3, v0, Ldn/b;->m:Landroid/graphics/RectF;

    .line 268
    .line 269
    const/4 v11, 0x0

    .line 270
    invoke-virtual {v6, v3, v11}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 271
    .line 272
    .line 273
    if-nez v15, :cond_d

    .line 274
    .line 275
    invoke-virtual {v2, v3}, Landroid/graphics/RectF;->set(Landroid/graphics/RectF;)V

    .line 276
    .line 277
    .line 278
    goto :goto_6

    .line 279
    :cond_d
    iget v14, v2, Landroid/graphics/RectF;->left:F

    .line 280
    .line 281
    iget v11, v3, Landroid/graphics/RectF;->left:F

    .line 282
    .line 283
    invoke-static {v14, v11}, Ljava/lang/Math;->min(FF)F

    .line 284
    .line 285
    .line 286
    move-result v11

    .line 287
    iget v14, v2, Landroid/graphics/RectF;->top:F

    .line 288
    .line 289
    move-object/from16 v17, v5

    .line 290
    .line 291
    iget v5, v3, Landroid/graphics/RectF;->top:F

    .line 292
    .line 293
    invoke-static {v14, v5}, Ljava/lang/Math;->min(FF)F

    .line 294
    .line 295
    .line 296
    move-result v5

    .line 297
    iget v14, v2, Landroid/graphics/RectF;->right:F

    .line 298
    .line 299
    move-object/from16 v18, v6

    .line 300
    .line 301
    iget v6, v3, Landroid/graphics/RectF;->right:F

    .line 302
    .line 303
    invoke-static {v14, v6}, Ljava/lang/Math;->max(FF)F

    .line 304
    .line 305
    .line 306
    move-result v6

    .line 307
    iget v14, v2, Landroid/graphics/RectF;->bottom:F

    .line 308
    .line 309
    iget v3, v3, Landroid/graphics/RectF;->bottom:F

    .line 310
    .line 311
    invoke-static {v14, v3}, Ljava/lang/Math;->max(FF)F

    .line 312
    .line 313
    .line 314
    move-result v3

    .line 315
    invoke-virtual {v2, v11, v5, v6, v3}, Landroid/graphics/RectF;->set(FFFF)V

    .line 316
    .line 317
    .line 318
    :goto_8
    add-int/lit8 v15, v15, 0x1

    .line 319
    .line 320
    move/from16 v3, v16

    .line 321
    .line 322
    move-object/from16 v5, v17

    .line 323
    .line 324
    move-object/from16 v6, v18

    .line 325
    .line 326
    const/4 v11, 0x1

    .line 327
    goto/16 :goto_5

    .line 328
    .line 329
    :cond_e
    move-object/from16 v17, v5

    .line 330
    .line 331
    move-object/from16 v18, v6

    .line 332
    .line 333
    invoke-virtual {v13, v2}, Landroid/graphics/RectF;->intersect(Landroid/graphics/RectF;)Z

    .line 334
    .line 335
    .line 336
    move-result v2

    .line 337
    if-nez v2, :cond_8

    .line 338
    .line 339
    const/4 v2, 0x0

    .line 340
    invoke-virtual {v13, v2, v2, v2, v2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 341
    .line 342
    .line 343
    :goto_9
    invoke-virtual {v1}, Landroid/graphics/Canvas;->getWidth()I

    .line 344
    .line 345
    .line 346
    move-result v3

    .line 347
    int-to-float v3, v3

    .line 348
    invoke-virtual {v1}, Landroid/graphics/Canvas;->getHeight()I

    .line 349
    .line 350
    .line 351
    move-result v5

    .line 352
    int-to-float v5, v5

    .line 353
    iget-object v6, v0, Ldn/b;->j:Landroid/graphics/RectF;

    .line 354
    .line 355
    invoke-virtual {v6, v2, v2, v3, v5}, Landroid/graphics/RectF;->set(FFFF)V

    .line 356
    .line 357
    .line 358
    iget-object v3, v0, Ldn/b;->c:Landroid/graphics/Matrix;

    .line 359
    .line 360
    invoke-virtual {v1, v3}, Landroid/graphics/Canvas;->getMatrix(Landroid/graphics/Matrix;)V

    .line 361
    .line 362
    .line 363
    invoke-virtual {v3}, Landroid/graphics/Matrix;->isIdentity()Z

    .line 364
    .line 365
    .line 366
    move-result v5

    .line 367
    if-nez v5, :cond_f

    .line 368
    .line 369
    invoke-virtual {v3, v3}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 370
    .line 371
    .line 372
    invoke-virtual {v3, v6}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 373
    .line 374
    .line 375
    :cond_f
    invoke-virtual {v13, v6}, Landroid/graphics/RectF;->intersect(Landroid/graphics/RectF;)Z

    .line 376
    .line 377
    .line 378
    move-result v3

    .line 379
    if-nez v3, :cond_10

    .line 380
    .line 381
    invoke-virtual {v13, v2, v2, v2, v2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 382
    .line 383
    .line 384
    :cond_10
    invoke-virtual {v13}, Landroid/graphics/RectF;->width()F

    .line 385
    .line 386
    .line 387
    move-result v2

    .line 388
    const/high16 v11, 0x3f800000    # 1.0f

    .line 389
    .line 390
    cmpl-float v2, v2, v11

    .line 391
    .line 392
    if-ltz v2, :cond_27

    .line 393
    .line 394
    invoke-virtual {v13}, Landroid/graphics/RectF;->height()F

    .line 395
    .line 396
    .line 397
    move-result v2

    .line 398
    cmpl-float v2, v2, v11

    .line 399
    .line 400
    if-ltz v2, :cond_27

    .line 401
    .line 402
    iget-object v14, v0, Ldn/b;->d:Ldn/i;

    .line 403
    .line 404
    const/16 v15, 0xff

    .line 405
    .line 406
    invoke-virtual {v14, v15}, Ldn/i;->setAlpha(I)V

    .line 407
    .line 408
    .line 409
    invoke-static {v4}, Lu/w;->o(I)I

    .line 410
    .line 411
    .line 412
    move-result v2

    .line 413
    const/4 v3, 0x4

    .line 414
    const/4 v5, 0x1

    .line 415
    if-eq v2, v5, :cond_15

    .line 416
    .line 417
    const/4 v5, 0x2

    .line 418
    if-eq v2, v5, :cond_14

    .line 419
    .line 420
    const/16 v5, 0x10

    .line 421
    .line 422
    const/4 v6, 0x3

    .line 423
    if-eq v2, v6, :cond_16

    .line 424
    .line 425
    if-eq v2, v3, :cond_13

    .line 426
    .line 427
    const/4 v6, 0x5

    .line 428
    if-eq v2, v6, :cond_12

    .line 429
    .line 430
    if-eq v2, v5, :cond_11

    .line 431
    .line 432
    const/4 v5, 0x0

    .line 433
    goto :goto_a

    .line 434
    :cond_11
    const/16 v5, 0xd

    .line 435
    .line 436
    goto :goto_a

    .line 437
    :cond_12
    const/16 v5, 0x12

    .line 438
    .line 439
    goto :goto_a

    .line 440
    :cond_13
    const/16 v5, 0x11

    .line 441
    .line 442
    goto :goto_a

    .line 443
    :cond_14
    const/16 v5, 0xf

    .line 444
    .line 445
    goto :goto_a

    .line 446
    :cond_15
    const/16 v5, 0x19

    .line 447
    .line 448
    :cond_16
    :goto_a
    sget v2, Ls5/c;->a:I

    .line 449
    .line 450
    if-eqz v5, :cond_17

    .line 451
    .line 452
    invoke-static {v5}, Lu/w;->o(I)I

    .line 453
    .line 454
    .line 455
    move-result v5

    .line 456
    packed-switch v5, :pswitch_data_0

    .line 457
    .line 458
    .line 459
    goto/16 :goto_b

    .line 460
    .line 461
    :pswitch_0
    sget-object v5, Landroid/graphics/BlendMode;->LUMINOSITY:Landroid/graphics/BlendMode;

    .line 462
    .line 463
    goto/16 :goto_c

    .line 464
    .line 465
    :pswitch_1
    sget-object v5, Landroid/graphics/BlendMode;->COLOR:Landroid/graphics/BlendMode;

    .line 466
    .line 467
    goto/16 :goto_c

    .line 468
    .line 469
    :pswitch_2
    sget-object v5, Landroid/graphics/BlendMode;->SATURATION:Landroid/graphics/BlendMode;

    .line 470
    .line 471
    goto/16 :goto_c

    .line 472
    .line 473
    :pswitch_3
    sget-object v5, Landroid/graphics/BlendMode;->HUE:Landroid/graphics/BlendMode;

    .line 474
    .line 475
    goto/16 :goto_c

    .line 476
    .line 477
    :pswitch_4
    sget-object v5, Landroid/graphics/BlendMode;->MULTIPLY:Landroid/graphics/BlendMode;

    .line 478
    .line 479
    goto :goto_c

    .line 480
    :pswitch_5
    sget-object v5, Landroid/graphics/BlendMode;->EXCLUSION:Landroid/graphics/BlendMode;

    .line 481
    .line 482
    goto :goto_c

    .line 483
    :pswitch_6
    sget-object v5, Landroid/graphics/BlendMode;->DIFFERENCE:Landroid/graphics/BlendMode;

    .line 484
    .line 485
    goto :goto_c

    .line 486
    :pswitch_7
    sget-object v5, Landroid/graphics/BlendMode;->SOFT_LIGHT:Landroid/graphics/BlendMode;

    .line 487
    .line 488
    goto :goto_c

    .line 489
    :pswitch_8
    sget-object v5, Landroid/graphics/BlendMode;->HARD_LIGHT:Landroid/graphics/BlendMode;

    .line 490
    .line 491
    goto :goto_c

    .line 492
    :pswitch_9
    sget-object v5, Landroid/graphics/BlendMode;->COLOR_BURN:Landroid/graphics/BlendMode;

    .line 493
    .line 494
    goto :goto_c

    .line 495
    :pswitch_a
    sget-object v5, Landroid/graphics/BlendMode;->COLOR_DODGE:Landroid/graphics/BlendMode;

    .line 496
    .line 497
    goto :goto_c

    .line 498
    :pswitch_b
    sget-object v5, Landroid/graphics/BlendMode;->LIGHTEN:Landroid/graphics/BlendMode;

    .line 499
    .line 500
    goto :goto_c

    .line 501
    :pswitch_c
    sget-object v5, Landroid/graphics/BlendMode;->DARKEN:Landroid/graphics/BlendMode;

    .line 502
    .line 503
    goto :goto_c

    .line 504
    :pswitch_d
    sget-object v5, Landroid/graphics/BlendMode;->OVERLAY:Landroid/graphics/BlendMode;

    .line 505
    .line 506
    goto :goto_c

    .line 507
    :pswitch_e
    sget-object v5, Landroid/graphics/BlendMode;->SCREEN:Landroid/graphics/BlendMode;

    .line 508
    .line 509
    goto :goto_c

    .line 510
    :pswitch_f
    sget-object v5, Landroid/graphics/BlendMode;->MODULATE:Landroid/graphics/BlendMode;

    .line 511
    .line 512
    goto :goto_c

    .line 513
    :pswitch_10
    sget-object v5, Landroid/graphics/BlendMode;->PLUS:Landroid/graphics/BlendMode;

    .line 514
    .line 515
    goto :goto_c

    .line 516
    :pswitch_11
    sget-object v5, Landroid/graphics/BlendMode;->XOR:Landroid/graphics/BlendMode;

    .line 517
    .line 518
    goto :goto_c

    .line 519
    :pswitch_12
    sget-object v5, Landroid/graphics/BlendMode;->DST_ATOP:Landroid/graphics/BlendMode;

    .line 520
    .line 521
    goto :goto_c

    .line 522
    :pswitch_13
    sget-object v5, Landroid/graphics/BlendMode;->SRC_ATOP:Landroid/graphics/BlendMode;

    .line 523
    .line 524
    goto :goto_c

    .line 525
    :pswitch_14
    sget-object v5, Landroid/graphics/BlendMode;->DST_OUT:Landroid/graphics/BlendMode;

    .line 526
    .line 527
    goto :goto_c

    .line 528
    :pswitch_15
    sget-object v5, Landroid/graphics/BlendMode;->SRC_OUT:Landroid/graphics/BlendMode;

    .line 529
    .line 530
    goto :goto_c

    .line 531
    :pswitch_16
    sget-object v5, Landroid/graphics/BlendMode;->DST_IN:Landroid/graphics/BlendMode;

    .line 532
    .line 533
    goto :goto_c

    .line 534
    :pswitch_17
    sget-object v5, Landroid/graphics/BlendMode;->SRC_IN:Landroid/graphics/BlendMode;

    .line 535
    .line 536
    goto :goto_c

    .line 537
    :pswitch_18
    sget-object v5, Landroid/graphics/BlendMode;->DST_OVER:Landroid/graphics/BlendMode;

    .line 538
    .line 539
    goto :goto_c

    .line 540
    :pswitch_19
    sget-object v5, Landroid/graphics/BlendMode;->SRC_OVER:Landroid/graphics/BlendMode;

    .line 541
    .line 542
    goto :goto_c

    .line 543
    :pswitch_1a
    sget-object v5, Landroid/graphics/BlendMode;->DST:Landroid/graphics/BlendMode;

    .line 544
    .line 545
    goto :goto_c

    .line 546
    :pswitch_1b
    sget-object v5, Landroid/graphics/BlendMode;->SRC:Landroid/graphics/BlendMode;

    .line 547
    .line 548
    goto :goto_c

    .line 549
    :pswitch_1c
    sget-object v5, Landroid/graphics/BlendMode;->CLEAR:Landroid/graphics/BlendMode;

    .line 550
    .line 551
    goto :goto_c

    .line 552
    :cond_17
    :goto_b
    const/4 v5, 0x0

    .line 553
    :goto_c
    invoke-virtual {v14, v5}, Landroid/graphics/Paint;->setBlendMode(Landroid/graphics/BlendMode;)V

    .line 554
    .line 555
    .line 556
    sget-object v5, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 557
    .line 558
    invoke-virtual {v1, v13, v14}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 559
    .line 560
    .line 561
    const/4 v5, 0x2

    .line 562
    if-eq v4, v5, :cond_18

    .line 563
    .line 564
    iget v4, v13, Landroid/graphics/RectF;->left:F

    .line 565
    .line 566
    sub-float/2addr v4, v11

    .line 567
    iget v5, v13, Landroid/graphics/RectF;->top:F

    .line 568
    .line 569
    sub-float/2addr v5, v11

    .line 570
    iget v6, v13, Landroid/graphics/RectF;->right:F

    .line 571
    .line 572
    add-float/2addr v6, v11

    .line 573
    iget v2, v13, Landroid/graphics/RectF;->bottom:F

    .line 574
    .line 575
    add-float/2addr v2, v11

    .line 576
    move/from16 v16, v3

    .line 577
    .line 578
    move v3, v5

    .line 579
    move v5, v2

    .line 580
    move v2, v4

    .line 581
    move v4, v6

    .line 582
    iget-object v6, v0, Ldn/b;->h:Ldn/i;

    .line 583
    .line 584
    move/from16 v19, v11

    .line 585
    .line 586
    move/from16 v11, v16

    .line 587
    .line 588
    move-object/from16 v15, v17

    .line 589
    .line 590
    move-object/from16 v20, v18

    .line 591
    .line 592
    invoke-virtual/range {v1 .. v6}, Landroid/graphics/Canvas;->drawRect(FFFFLandroid/graphics/Paint;)V

    .line 593
    .line 594
    .line 595
    goto :goto_d

    .line 596
    :cond_18
    move/from16 v19, v11

    .line 597
    .line 598
    move-object/from16 v15, v17

    .line 599
    .line 600
    move-object/from16 v20, v18

    .line 601
    .line 602
    move v11, v3

    .line 603
    :goto_d
    invoke-virtual {v0, v1, v10, v12, v9}, Ldn/b;->h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 604
    .line 605
    .line 606
    invoke-virtual {v0}, Ldn/b;->j()Z

    .line 607
    .line 608
    .line 609
    move-result v2

    .line 610
    if-eqz v2, :cond_25

    .line 611
    .line 612
    iget-object v2, v0, Ldn/b;->e:Ldn/i;

    .line 613
    .line 614
    invoke-virtual {v1, v13, v2}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 615
    .line 616
    .line 617
    const/4 v3, 0x0

    .line 618
    :goto_e
    iget-object v4, v15, Lrn/i;->g:Ljava/lang/Object;

    .line 619
    .line 620
    check-cast v4, Ljava/util/List;

    .line 621
    .line 622
    iget-object v5, v15, Lrn/i;->e:Ljava/lang/Object;

    .line 623
    .line 624
    check-cast v5, Ljava/util/ArrayList;

    .line 625
    .line 626
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 627
    .line 628
    .line 629
    move-result v6

    .line 630
    if-ge v3, v6, :cond_24

    .line 631
    .line 632
    invoke-interface {v4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 633
    .line 634
    .line 635
    move-result-object v6

    .line 636
    check-cast v6, Lcn/f;

    .line 637
    .line 638
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 639
    .line 640
    .line 641
    move-result-object v9

    .line 642
    check-cast v9, Lxm/e;

    .line 643
    .line 644
    iget-object v12, v15, Lrn/i;->f:Ljava/lang/Object;

    .line 645
    .line 646
    check-cast v12, Ljava/util/ArrayList;

    .line 647
    .line 648
    invoke-virtual {v12, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 649
    .line 650
    .line 651
    move-result-object v12

    .line 652
    check-cast v12, Lxm/e;

    .line 653
    .line 654
    iget v11, v6, Lcn/f;->a:I

    .line 655
    .line 656
    iget-boolean v6, v6, Lcn/f;->d:Z

    .line 657
    .line 658
    invoke-static {v11}, Lu/w;->o(I)I

    .line 659
    .line 660
    .line 661
    move-result v11

    .line 662
    move/from16 v17, v3

    .line 663
    .line 664
    iget-object v3, v0, Ldn/b;->f:Ldn/i;

    .line 665
    .line 666
    const v18, 0x40233333    # 2.55f

    .line 667
    .line 668
    .line 669
    if-eqz v11, :cond_22

    .line 670
    .line 671
    move-object/from16 p4, v5

    .line 672
    .line 673
    const/4 v5, 0x1

    .line 674
    if-eq v11, v5, :cond_1f

    .line 675
    .line 676
    const/4 v5, 0x2

    .line 677
    if-eq v11, v5, :cond_1d

    .line 678
    .line 679
    const/4 v5, 0x3

    .line 680
    if-eq v11, v5, :cond_19

    .line 681
    .line 682
    move-object/from16 v4, v20

    .line 683
    .line 684
    const/16 v5, 0xff

    .line 685
    .line 686
    const/4 v11, 0x4

    .line 687
    goto/16 :goto_14

    .line 688
    .line 689
    :cond_19
    invoke-virtual/range {p4 .. p4}, Ljava/util/ArrayList;->isEmpty()Z

    .line 690
    .line 691
    .line 692
    move-result v3

    .line 693
    if-eqz v3, :cond_1a

    .line 694
    .line 695
    const/4 v11, 0x4

    .line 696
    goto :goto_10

    .line 697
    :cond_1a
    const/4 v3, 0x0

    .line 698
    :goto_f
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 699
    .line 700
    .line 701
    move-result v6

    .line 702
    if-ge v3, v6, :cond_1c

    .line 703
    .line 704
    invoke-interface {v4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 705
    .line 706
    .line 707
    move-result-object v6

    .line 708
    check-cast v6, Lcn/f;

    .line 709
    .line 710
    iget v6, v6, Lcn/f;->a:I

    .line 711
    .line 712
    const/4 v11, 0x4

    .line 713
    if-eq v6, v11, :cond_1b

    .line 714
    .line 715
    :goto_10
    move-object/from16 v4, v20

    .line 716
    .line 717
    :goto_11
    const/16 v5, 0xff

    .line 718
    .line 719
    goto/16 :goto_14

    .line 720
    .line 721
    :cond_1b
    add-int/lit8 v3, v3, 0x1

    .line 722
    .line 723
    goto :goto_f

    .line 724
    :cond_1c
    const/16 v3, 0xff

    .line 725
    .line 726
    const/4 v11, 0x4

    .line 727
    invoke-virtual {v14, v3}, Ldn/i;->setAlpha(I)V

    .line 728
    .line 729
    .line 730
    invoke-virtual {v1, v13, v14}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    .line 731
    .line 732
    .line 733
    goto :goto_10

    .line 734
    :cond_1d
    const/4 v5, 0x3

    .line 735
    const/4 v11, 0x4

    .line 736
    if-eqz v6, :cond_1e

    .line 737
    .line 738
    sget-object v4, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 739
    .line 740
    invoke-virtual {v1, v13, v2}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 741
    .line 742
    .line 743
    invoke-virtual {v1, v13, v14}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    .line 744
    .line 745
    .line 746
    invoke-virtual {v12}, Lxm/e;->d()Ljava/lang/Object;

    .line 747
    .line 748
    .line 749
    move-result-object v4

    .line 750
    check-cast v4, Ljava/lang/Integer;

    .line 751
    .line 752
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 753
    .line 754
    .line 755
    move-result v4

    .line 756
    int-to-float v4, v4

    .line 757
    mul-float v4, v4, v18

    .line 758
    .line 759
    float-to-int v4, v4

    .line 760
    invoke-virtual {v3, v4}, Ldn/i;->setAlpha(I)V

    .line 761
    .line 762
    .line 763
    invoke-virtual {v9}, Lxm/e;->d()Ljava/lang/Object;

    .line 764
    .line 765
    .line 766
    move-result-object v4

    .line 767
    check-cast v4, Landroid/graphics/Path;

    .line 768
    .line 769
    move-object/from16 v6, v20

    .line 770
    .line 771
    invoke-virtual {v6, v4}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 772
    .line 773
    .line 774
    invoke-virtual {v6, v10}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 775
    .line 776
    .line 777
    invoke-virtual {v1, v6, v3}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 778
    .line 779
    .line 780
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 781
    .line 782
    .line 783
    :goto_12
    move-object v4, v6

    .line 784
    goto :goto_11

    .line 785
    :cond_1e
    move-object/from16 v6, v20

    .line 786
    .line 787
    sget-object v3, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 788
    .line 789
    invoke-virtual {v1, v13, v2}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 790
    .line 791
    .line 792
    invoke-virtual {v9}, Lxm/e;->d()Ljava/lang/Object;

    .line 793
    .line 794
    .line 795
    move-result-object v3

    .line 796
    check-cast v3, Landroid/graphics/Path;

    .line 797
    .line 798
    invoke-virtual {v6, v3}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 799
    .line 800
    .line 801
    invoke-virtual {v6, v10}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 802
    .line 803
    .line 804
    invoke-virtual {v12}, Lxm/e;->d()Ljava/lang/Object;

    .line 805
    .line 806
    .line 807
    move-result-object v3

    .line 808
    check-cast v3, Ljava/lang/Integer;

    .line 809
    .line 810
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 811
    .line 812
    .line 813
    move-result v3

    .line 814
    int-to-float v3, v3

    .line 815
    mul-float v3, v3, v18

    .line 816
    .line 817
    float-to-int v3, v3

    .line 818
    invoke-virtual {v14, v3}, Ldn/i;->setAlpha(I)V

    .line 819
    .line 820
    .line 821
    invoke-virtual {v1, v6, v14}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 822
    .line 823
    .line 824
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 825
    .line 826
    .line 827
    goto :goto_12

    .line 828
    :cond_1f
    move-object/from16 v4, v20

    .line 829
    .line 830
    const/4 v5, 0x3

    .line 831
    const/4 v11, 0x4

    .line 832
    if-nez v17, :cond_20

    .line 833
    .line 834
    const/high16 v5, -0x1000000

    .line 835
    .line 836
    invoke-virtual {v14, v5}, Landroid/graphics/Paint;->setColor(I)V

    .line 837
    .line 838
    .line 839
    const/16 v5, 0xff

    .line 840
    .line 841
    invoke-virtual {v14, v5}, Ldn/i;->setAlpha(I)V

    .line 842
    .line 843
    .line 844
    invoke-virtual {v1, v13, v14}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    .line 845
    .line 846
    .line 847
    goto :goto_13

    .line 848
    :cond_20
    const/16 v5, 0xff

    .line 849
    .line 850
    :goto_13
    if-eqz v6, :cond_21

    .line 851
    .line 852
    sget-object v6, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 853
    .line 854
    invoke-virtual {v1, v13, v3}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 855
    .line 856
    .line 857
    invoke-virtual {v1, v13, v14}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    .line 858
    .line 859
    .line 860
    invoke-virtual {v12}, Lxm/e;->d()Ljava/lang/Object;

    .line 861
    .line 862
    .line 863
    move-result-object v6

    .line 864
    check-cast v6, Ljava/lang/Integer;

    .line 865
    .line 866
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 867
    .line 868
    .line 869
    move-result v6

    .line 870
    int-to-float v6, v6

    .line 871
    mul-float v6, v6, v18

    .line 872
    .line 873
    float-to-int v6, v6

    .line 874
    invoke-virtual {v3, v6}, Ldn/i;->setAlpha(I)V

    .line 875
    .line 876
    .line 877
    invoke-virtual {v9}, Lxm/e;->d()Ljava/lang/Object;

    .line 878
    .line 879
    .line 880
    move-result-object v6

    .line 881
    check-cast v6, Landroid/graphics/Path;

    .line 882
    .line 883
    invoke-virtual {v4, v6}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 884
    .line 885
    .line 886
    invoke-virtual {v4, v10}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 887
    .line 888
    .line 889
    invoke-virtual {v1, v4, v3}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 890
    .line 891
    .line 892
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 893
    .line 894
    .line 895
    goto :goto_14

    .line 896
    :cond_21
    invoke-virtual {v9}, Lxm/e;->d()Ljava/lang/Object;

    .line 897
    .line 898
    .line 899
    move-result-object v6

    .line 900
    check-cast v6, Landroid/graphics/Path;

    .line 901
    .line 902
    invoke-virtual {v4, v6}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 903
    .line 904
    .line 905
    invoke-virtual {v4, v10}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 906
    .line 907
    .line 908
    invoke-virtual {v1, v4, v3}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 909
    .line 910
    .line 911
    goto :goto_14

    .line 912
    :cond_22
    move-object/from16 v4, v20

    .line 913
    .line 914
    const/16 v5, 0xff

    .line 915
    .line 916
    const/4 v11, 0x4

    .line 917
    if-eqz v6, :cond_23

    .line 918
    .line 919
    sget-object v6, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 920
    .line 921
    invoke-virtual {v1, v13, v14}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 922
    .line 923
    .line 924
    invoke-virtual {v1, v13, v14}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    .line 925
    .line 926
    .line 927
    invoke-virtual {v9}, Lxm/e;->d()Ljava/lang/Object;

    .line 928
    .line 929
    .line 930
    move-result-object v6

    .line 931
    check-cast v6, Landroid/graphics/Path;

    .line 932
    .line 933
    invoke-virtual {v4, v6}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 934
    .line 935
    .line 936
    invoke-virtual {v4, v10}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 937
    .line 938
    .line 939
    invoke-virtual {v12}, Lxm/e;->d()Ljava/lang/Object;

    .line 940
    .line 941
    .line 942
    move-result-object v6

    .line 943
    check-cast v6, Ljava/lang/Integer;

    .line 944
    .line 945
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 946
    .line 947
    .line 948
    move-result v6

    .line 949
    int-to-float v6, v6

    .line 950
    mul-float v6, v6, v18

    .line 951
    .line 952
    float-to-int v6, v6

    .line 953
    invoke-virtual {v14, v6}, Ldn/i;->setAlpha(I)V

    .line 954
    .line 955
    .line 956
    invoke-virtual {v1, v4, v3}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 957
    .line 958
    .line 959
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 960
    .line 961
    .line 962
    goto :goto_14

    .line 963
    :cond_23
    invoke-virtual {v9}, Lxm/e;->d()Ljava/lang/Object;

    .line 964
    .line 965
    .line 966
    move-result-object v3

    .line 967
    check-cast v3, Landroid/graphics/Path;

    .line 968
    .line 969
    invoke-virtual {v4, v3}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 970
    .line 971
    .line 972
    invoke-virtual {v4, v10}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 973
    .line 974
    .line 975
    invoke-virtual {v12}, Lxm/e;->d()Ljava/lang/Object;

    .line 976
    .line 977
    .line 978
    move-result-object v3

    .line 979
    check-cast v3, Ljava/lang/Integer;

    .line 980
    .line 981
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 982
    .line 983
    .line 984
    move-result v3

    .line 985
    int-to-float v3, v3

    .line 986
    mul-float v3, v3, v18

    .line 987
    .line 988
    float-to-int v3, v3

    .line 989
    invoke-virtual {v14, v3}, Ldn/i;->setAlpha(I)V

    .line 990
    .line 991
    .line 992
    invoke-virtual {v1, v4, v14}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 993
    .line 994
    .line 995
    :goto_14
    add-int/lit8 v3, v17, 0x1

    .line 996
    .line 997
    move-object/from16 v20, v4

    .line 998
    .line 999
    goto/16 :goto_e

    .line 1000
    .line 1001
    :cond_24
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 1002
    .line 1003
    .line 1004
    :cond_25
    iget-object v2, v0, Ldn/b;->s:Ldn/b;

    .line 1005
    .line 1006
    if-eqz v2, :cond_26

    .line 1007
    .line 1008
    iget-object v2, v0, Ldn/b;->g:Ldn/i;

    .line 1009
    .line 1010
    invoke-virtual {v1, v13, v2}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;)I

    .line 1011
    .line 1012
    .line 1013
    iget v2, v13, Landroid/graphics/RectF;->left:F

    .line 1014
    .line 1015
    sub-float v2, v2, v19

    .line 1016
    .line 1017
    iget v3, v13, Landroid/graphics/RectF;->top:F

    .line 1018
    .line 1019
    sub-float v3, v3, v19

    .line 1020
    .line 1021
    iget v4, v13, Landroid/graphics/RectF;->right:F

    .line 1022
    .line 1023
    add-float v4, v4, v19

    .line 1024
    .line 1025
    iget v5, v13, Landroid/graphics/RectF;->bottom:F

    .line 1026
    .line 1027
    add-float v5, v5, v19

    .line 1028
    .line 1029
    iget-object v6, v0, Ldn/b;->h:Ldn/i;

    .line 1030
    .line 1031
    invoke-virtual/range {v1 .. v6}, Landroid/graphics/Canvas;->drawRect(FFFFLandroid/graphics/Paint;)V

    .line 1032
    .line 1033
    .line 1034
    iget-object v2, v0, Ldn/b;->s:Ldn/b;

    .line 1035
    .line 1036
    const/4 v3, 0x0

    .line 1037
    invoke-virtual {v2, v1, v7, v8, v3}, Ldn/b;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 1038
    .line 1039
    .line 1040
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 1041
    .line 1042
    .line 1043
    :cond_26
    invoke-virtual {v1}, Landroid/graphics/Canvas;->restore()V

    .line 1044
    .line 1045
    .line 1046
    :cond_27
    invoke-virtual {v0}, Ldn/b;->k()V

    .line 1047
    .line 1048
    .line 1049
    :cond_28
    :goto_15
    return-void

    .line 1050
    nop

    .line 1051
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 1

    .line 1
    iget-object p1, p0, Ldn/b;->i:Landroid/graphics/RectF;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p1, v0, v0, v0, v0}, Landroid/graphics/RectF;->set(FFFF)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Ldn/b;->g()V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Ldn/b;->n:Landroid/graphics/Matrix;

    .line 11
    .line 12
    invoke-virtual {p1, p2}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 13
    .line 14
    .line 15
    if-eqz p3, :cond_1

    .line 16
    .line 17
    iget-object p2, p0, Ldn/b;->u:Ljava/util/List;

    .line 18
    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    add-int/lit8 p2, p2, -0x1

    .line 26
    .line 27
    :goto_0
    if-ltz p2, :cond_1

    .line 28
    .line 29
    iget-object p3, p0, Ldn/b;->u:Ljava/util/List;

    .line 30
    .line 31
    invoke-interface {p3, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p3

    .line 35
    check-cast p3, Ldn/b;

    .line 36
    .line 37
    iget-object p3, p3, Ldn/b;->w:Lxm/n;

    .line 38
    .line 39
    invoke-virtual {p3}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 40
    .line 41
    .line 42
    move-result-object p3

    .line 43
    invoke-virtual {p1, p3}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 44
    .line 45
    .line 46
    add-int/lit8 p2, p2, -0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    iget-object p2, p0, Ldn/b;->t:Ldn/b;

    .line 50
    .line 51
    if-eqz p2, :cond_1

    .line 52
    .line 53
    iget-object p2, p2, Ldn/b;->w:Lxm/n;

    .line 54
    .line 55
    invoke-virtual {p2}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    invoke-virtual {p1, p2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 60
    .line 61
    .line 62
    :cond_1
    iget-object p0, p0, Ldn/b;->w:Lxm/n;

    .line 63
    .line 64
    invoke-virtual {p0}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-virtual {p1, p0}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public final f(Lxm/e;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object p0, p0, Ldn/b;->v:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final g()V
    .locals 2

    .line 1
    iget-object v0, p0, Ldn/b;->u:Ljava/util/List;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto :goto_1

    .line 6
    :cond_0
    iget-object v0, p0, Ldn/b;->t:Ldn/b;

    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 11
    .line 12
    iput-object v0, p0, Ldn/b;->u:Ljava/util/List;

    .line 13
    .line 14
    return-void

    .line 15
    :cond_1
    new-instance v0, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Ldn/b;->u:Ljava/util/List;

    .line 21
    .line 22
    iget-object v0, p0, Ldn/b;->t:Ldn/b;

    .line 23
    .line 24
    :goto_0
    if-eqz v0, :cond_2

    .line 25
    .line 26
    iget-object v1, p0, Ldn/b;->u:Ljava/util/List;

    .line 27
    .line 28
    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    iget-object v0, v0, Ldn/b;->t:Ldn/b;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    :goto_1
    return-void
.end method

.method public abstract h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
.end method

.method public i()Laq/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ldn/b;->p:Ldn/e;

    .line 2
    .line 3
    iget-object p0, p0, Ldn/e;->w:Laq/a;

    .line 4
    .line 5
    return-object p0
.end method

.method public final j()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ldn/b;->q:Lrn/i;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final k()V
    .locals 1

    .line 1
    iget-object v0, p0, Ldn/b;->o:Lum/j;

    .line 2
    .line 3
    iget-object v0, v0, Lum/j;->d:Lum/a;

    .line 4
    .line 5
    iget-object v0, v0, Lum/a;->a:Li21/a;

    .line 6
    .line 7
    iget-object p0, p0, Ldn/b;->p:Ldn/e;

    .line 8
    .line 9
    iget-object p0, p0, Ldn/e;->c:Ljava/lang/String;

    .line 10
    .line 11
    iget-object p0, v0, Li21/a;->a:Ljava/util/HashMap;

    .line 12
    .line 13
    return-void
.end method

.method public l(F)V
    .locals 4

    .line 1
    iget-object v0, p0, Ldn/b;->w:Lxm/n;

    .line 2
    .line 3
    iget-object v1, v0, Lxm/n;->j:Lxm/f;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object v1, v0, Lxm/n;->m:Lxm/f;

    .line 11
    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 15
    .line 16
    .line 17
    :cond_1
    iget-object v1, v0, Lxm/n;->n:Lxm/f;

    .line 18
    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 22
    .line 23
    .line 24
    :cond_2
    iget-object v1, v0, Lxm/n;->f:Lxm/i;

    .line 25
    .line 26
    if-eqz v1, :cond_3

    .line 27
    .line 28
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 29
    .line 30
    .line 31
    :cond_3
    iget-object v1, v0, Lxm/n;->g:Lxm/e;

    .line 32
    .line 33
    if-eqz v1, :cond_4

    .line 34
    .line 35
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 36
    .line 37
    .line 38
    :cond_4
    iget-object v1, v0, Lxm/n;->h:Lxm/h;

    .line 39
    .line 40
    if-eqz v1, :cond_5

    .line 41
    .line 42
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 43
    .line 44
    .line 45
    :cond_5
    iget-object v1, v0, Lxm/n;->i:Lxm/f;

    .line 46
    .line 47
    if-eqz v1, :cond_6

    .line 48
    .line 49
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 50
    .line 51
    .line 52
    :cond_6
    iget-object v1, v0, Lxm/n;->k:Lxm/f;

    .line 53
    .line 54
    if-eqz v1, :cond_7

    .line 55
    .line 56
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 57
    .line 58
    .line 59
    :cond_7
    iget-object v0, v0, Lxm/n;->l:Lxm/f;

    .line 60
    .line 61
    if-eqz v0, :cond_8

    .line 62
    .line 63
    invoke-virtual {v0, p1}, Lxm/e;->g(F)V

    .line 64
    .line 65
    .line 66
    :cond_8
    const/4 v0, 0x0

    .line 67
    iget-object v1, p0, Ldn/b;->q:Lrn/i;

    .line 68
    .line 69
    if-eqz v1, :cond_9

    .line 70
    .line 71
    iget-object v1, v1, Lrn/i;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v1, Ljava/util/ArrayList;

    .line 74
    .line 75
    move v2, v0

    .line 76
    :goto_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-ge v2, v3, :cond_9

    .line 81
    .line 82
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    check-cast v3, Lxm/e;

    .line 87
    .line 88
    invoke-virtual {v3, p1}, Lxm/e;->g(F)V

    .line 89
    .line 90
    .line 91
    add-int/lit8 v2, v2, 0x1

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_9
    iget-object v1, p0, Ldn/b;->r:Lxm/f;

    .line 95
    .line 96
    if-eqz v1, :cond_a

    .line 97
    .line 98
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 99
    .line 100
    .line 101
    :cond_a
    iget-object v1, p0, Ldn/b;->s:Ldn/b;

    .line 102
    .line 103
    if-eqz v1, :cond_b

    .line 104
    .line 105
    invoke-virtual {v1, p1}, Ldn/b;->l(F)V

    .line 106
    .line 107
    .line 108
    :cond_b
    :goto_1
    iget-object v1, p0, Ldn/b;->v:Ljava/util/ArrayList;

    .line 109
    .line 110
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    if-ge v0, v2, :cond_c

    .line 115
    .line 116
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    check-cast v1, Lxm/e;

    .line 121
    .line 122
    invoke-virtual {v1, p1}, Lxm/e;->g(F)V

    .line 123
    .line 124
    .line 125
    add-int/lit8 v0, v0, 0x1

    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_c
    return-void
.end method

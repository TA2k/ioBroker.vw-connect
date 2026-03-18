.class public final Lh3/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final y:Lh3/e;


# instance fields
.field public final a:Lh3/d;

.field public b:Lt4/c;

.field public c:Lt4/m;

.field public d:Lay0/k;

.field public final e:La3/f;

.field public f:Landroid/graphics/Outline;

.field public g:Z

.field public h:J

.field public i:J

.field public j:F

.field public k:Le3/g0;

.field public l:Le3/i;

.field public m:Le3/i;

.field public n:Z

.field public o:Lg3/b;

.field public p:Le3/g;

.field public q:I

.field public final r:Lvv0/d;

.field public s:Z

.field public t:J

.field public u:J

.field public v:J

.field public w:Z

.field public x:Landroid/graphics/RectF;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    .line 2
    .line 3
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "toLowerCase(...)"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v1, "robolectric"

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    sget-object v0, Lh3/f;->b:Lh3/f;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    sget-object v0, Lh3/f;->c:Lh3/f;

    .line 26
    .line 27
    :goto_0
    sput-object v0, Lh3/c;->y:Lh3/e;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>(Lh3/d;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh3/c;->a:Lh3/d;

    .line 5
    .line 6
    sget-object v0, Lg3/c;->a:Lt4/d;

    .line 7
    .line 8
    iput-object v0, p0, Lh3/c;->b:Lt4/c;

    .line 9
    .line 10
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 11
    .line 12
    iput-object v0, p0, Lh3/c;->c:Lt4/m;

    .line 13
    .line 14
    sget-object v0, Lh3/a;->f:Lh3/a;

    .line 15
    .line 16
    iput-object v0, p0, Lh3/c;->d:Lay0/k;

    .line 17
    .line 18
    new-instance v0, La3/f;

    .line 19
    .line 20
    const/16 v1, 0xf

    .line 21
    .line 22
    invoke-direct {v0, p0, v1}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lh3/c;->e:La3/f;

    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    iput-boolean v0, p0, Lh3/c;->g:Z

    .line 29
    .line 30
    const-wide/16 v0, 0x0

    .line 31
    .line 32
    iput-wide v0, p0, Lh3/c;->h:J

    .line 33
    .line 34
    const-wide v2, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    iput-wide v2, p0, Lh3/c;->i:J

    .line 40
    .line 41
    new-instance v4, Lvv0/d;

    .line 42
    .line 43
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 44
    .line 45
    .line 46
    iput-object v4, p0, Lh3/c;->r:Lvv0/d;

    .line 47
    .line 48
    const/4 v4, 0x0

    .line 49
    invoke-virtual {p1, v4}, Lh3/d;->c(Z)V

    .line 50
    .line 51
    .line 52
    iput-wide v0, p0, Lh3/c;->t:J

    .line 53
    .line 54
    iput-wide v0, p0, Lh3/c;->u:J

    .line 55
    .line 56
    iput-wide v2, p0, Lh3/c;->v:J

    .line 57
    .line 58
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lh3/c;->a:Lh3/d;

    .line 4
    .line 5
    iget-object v2, v1, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 6
    .line 7
    iget-boolean v3, v0, Lh3/c;->g:Z

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    if-eqz v3, :cond_c

    .line 11
    .line 12
    iget-boolean v3, v0, Lh3/c;->w:Z

    .line 13
    .line 14
    if-nez v3, :cond_1

    .line 15
    .line 16
    iget v5, v1, Lh3/d;->n:F

    .line 17
    .line 18
    const/4 v6, 0x0

    .line 19
    cmpl-float v5, v5, v6

    .line 20
    .line 21
    if-lez v5, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v1, v4}, Lh3/d;->c(Z)V

    .line 25
    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-virtual {v2, v3}, Landroid/graphics/RenderNode;->setOutline(Landroid/graphics/Outline;)Z

    .line 29
    .line 30
    .line 31
    iput-boolean v4, v1, Lh3/d;->g:Z

    .line 32
    .line 33
    invoke-virtual {v1}, Lh3/d;->a()V

    .line 34
    .line 35
    .line 36
    goto/16 :goto_3

    .line 37
    .line 38
    :cond_1
    :goto_0
    iget-object v5, v0, Lh3/c;->l:Le3/i;

    .line 39
    .line 40
    const/4 v6, 0x1

    .line 41
    if-eqz v5, :cond_9

    .line 42
    .line 43
    iget-object v3, v0, Lh3/c;->x:Landroid/graphics/RectF;

    .line 44
    .line 45
    if-nez v3, :cond_2

    .line 46
    .line 47
    new-instance v3, Landroid/graphics/RectF;

    .line 48
    .line 49
    invoke-direct {v3}, Landroid/graphics/RectF;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object v3, v0, Lh3/c;->x:Landroid/graphics/RectF;

    .line 53
    .line 54
    :cond_2
    instance-of v7, v5, Le3/i;

    .line 55
    .line 56
    const-string v8, "Unable to obtain android.graphics.Path"

    .line 57
    .line 58
    if-eqz v7, :cond_8

    .line 59
    .line 60
    iget-object v9, v5, Le3/i;->a:Landroid/graphics/Path;

    .line 61
    .line 62
    invoke-virtual {v9, v3, v4}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 63
    .line 64
    .line 65
    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 66
    .line 67
    iget-object v10, v0, Lh3/c;->f:Landroid/graphics/Outline;

    .line 68
    .line 69
    if-nez v10, :cond_3

    .line 70
    .line 71
    new-instance v10, Landroid/graphics/Outline;

    .line 72
    .line 73
    invoke-direct {v10}, Landroid/graphics/Outline;-><init>()V

    .line 74
    .line 75
    .line 76
    iput-object v10, v0, Lh3/c;->f:Landroid/graphics/Outline;

    .line 77
    .line 78
    :cond_3
    const/16 v11, 0x1e

    .line 79
    .line 80
    if-lt v9, v11, :cond_5

    .line 81
    .line 82
    if-eqz v7, :cond_4

    .line 83
    .line 84
    iget-object v7, v5, Le3/i;->a:Landroid/graphics/Path;

    .line 85
    .line 86
    invoke-static {v10, v7}, Ld6/t1;->j(Landroid/graphics/Outline;Landroid/graphics/Path;)V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_4
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 91
    .line 92
    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw v0

    .line 96
    :cond_5
    if-eqz v7, :cond_7

    .line 97
    .line 98
    iget-object v7, v5, Le3/i;->a:Landroid/graphics/Path;

    .line 99
    .line 100
    invoke-virtual {v10, v7}, Landroid/graphics/Outline;->setConvexPath(Landroid/graphics/Path;)V

    .line 101
    .line 102
    .line 103
    :goto_1
    invoke-virtual {v10}, Landroid/graphics/Outline;->canClip()Z

    .line 104
    .line 105
    .line 106
    move-result v7

    .line 107
    xor-int/2addr v7, v6

    .line 108
    iput-boolean v7, v0, Lh3/c;->n:Z

    .line 109
    .line 110
    iput-object v5, v0, Lh3/c;->l:Le3/i;

    .line 111
    .line 112
    iget v5, v1, Lh3/d;->h:F

    .line 113
    .line 114
    invoke-virtual {v10, v5}, Landroid/graphics/Outline;->setAlpha(F)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v3}, Landroid/graphics/RectF;->width()F

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 122
    .line 123
    .line 124
    invoke-virtual {v3}, Landroid/graphics/RectF;->height()F

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 129
    .line 130
    .line 131
    invoke-virtual {v2, v10}, Landroid/graphics/RenderNode;->setOutline(Landroid/graphics/Outline;)Z

    .line 132
    .line 133
    .line 134
    iput-boolean v6, v1, Lh3/d;->g:Z

    .line 135
    .line 136
    invoke-virtual {v1}, Lh3/d;->a()V

    .line 137
    .line 138
    .line 139
    iget-boolean v3, v0, Lh3/c;->n:Z

    .line 140
    .line 141
    if-eqz v3, :cond_6

    .line 142
    .line 143
    iget-boolean v3, v0, Lh3/c;->w:Z

    .line 144
    .line 145
    if-eqz v3, :cond_6

    .line 146
    .line 147
    invoke-virtual {v1, v4}, Lh3/d;->c(Z)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v2}, Landroid/graphics/RenderNode;->discardDisplayList()V

    .line 151
    .line 152
    .line 153
    goto/16 :goto_3

    .line 154
    .line 155
    :cond_6
    iget-boolean v2, v0, Lh3/c;->w:Z

    .line 156
    .line 157
    invoke-virtual {v1, v2}, Lh3/d;->c(Z)V

    .line 158
    .line 159
    .line 160
    goto/16 :goto_3

    .line 161
    .line 162
    :cond_7
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 163
    .line 164
    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    throw v0

    .line 168
    :cond_8
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 169
    .line 170
    invoke-direct {v0, v8}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    throw v0

    .line 174
    :cond_9
    invoke-virtual {v1, v3}, Lh3/d;->c(Z)V

    .line 175
    .line 176
    .line 177
    iget-object v3, v0, Lh3/c;->f:Landroid/graphics/Outline;

    .line 178
    .line 179
    if-nez v3, :cond_a

    .line 180
    .line 181
    new-instance v3, Landroid/graphics/Outline;

    .line 182
    .line 183
    invoke-direct {v3}, Landroid/graphics/Outline;-><init>()V

    .line 184
    .line 185
    .line 186
    iput-object v3, v0, Lh3/c;->f:Landroid/graphics/Outline;

    .line 187
    .line 188
    :cond_a
    move-object v7, v3

    .line 189
    iget-wide v8, v0, Lh3/c;->u:J

    .line 190
    .line 191
    invoke-static {v8, v9}, Lkp/f9;->c(J)J

    .line 192
    .line 193
    .line 194
    move-result-wide v8

    .line 195
    iget-wide v10, v0, Lh3/c;->h:J

    .line 196
    .line 197
    iget-wide v12, v0, Lh3/c;->i:J

    .line 198
    .line 199
    const-wide v14, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 200
    .line 201
    .line 202
    .line 203
    .line 204
    cmp-long v3, v12, v14

    .line 205
    .line 206
    if-nez v3, :cond_b

    .line 207
    .line 208
    goto :goto_2

    .line 209
    :cond_b
    move-wide v8, v12

    .line 210
    :goto_2
    const/16 v3, 0x20

    .line 211
    .line 212
    shr-long v12, v10, v3

    .line 213
    .line 214
    long-to-int v5, v12

    .line 215
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 216
    .line 217
    .line 218
    move-result v12

    .line 219
    invoke-static {v12}, Ljava/lang/Math;->round(F)I

    .line 220
    .line 221
    .line 222
    move-result v12

    .line 223
    const-wide v13, 0xffffffffL

    .line 224
    .line 225
    .line 226
    .line 227
    .line 228
    and-long/2addr v10, v13

    .line 229
    long-to-int v10, v10

    .line 230
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 231
    .line 232
    .line 233
    move-result v11

    .line 234
    invoke-static {v11}, Ljava/lang/Math;->round(F)I

    .line 235
    .line 236
    .line 237
    move-result v11

    .line 238
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 239
    .line 240
    .line 241
    move-result v5

    .line 242
    move-wide v15, v13

    .line 243
    shr-long v13, v8, v3

    .line 244
    .line 245
    long-to-int v3, v13

    .line 246
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 247
    .line 248
    .line 249
    move-result v13

    .line 250
    add-float/2addr v13, v5

    .line 251
    invoke-static {v13}, Ljava/lang/Math;->round(F)I

    .line 252
    .line 253
    .line 254
    move-result v5

    .line 255
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 256
    .line 257
    .line 258
    move-result v10

    .line 259
    and-long/2addr v8, v15

    .line 260
    long-to-int v13, v8

    .line 261
    invoke-static {v13}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 262
    .line 263
    .line 264
    move-result v8

    .line 265
    add-float/2addr v8, v10

    .line 266
    invoke-static {v8}, Ljava/lang/Math;->round(F)I

    .line 267
    .line 268
    .line 269
    move-result v8

    .line 270
    move v9, v11

    .line 271
    move v11, v8

    .line 272
    move v8, v12

    .line 273
    iget v12, v0, Lh3/c;->j:F

    .line 274
    .line 275
    move v10, v5

    .line 276
    invoke-virtual/range {v7 .. v12}, Landroid/graphics/Outline;->setRoundRect(IIIIF)V

    .line 277
    .line 278
    .line 279
    iget v5, v1, Lh3/d;->h:F

    .line 280
    .line 281
    invoke-virtual {v7, v5}, Landroid/graphics/Outline;->setAlpha(F)V

    .line 282
    .line 283
    .line 284
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 285
    .line 286
    .line 287
    move-result v3

    .line 288
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 289
    .line 290
    .line 291
    invoke-static {v13}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 292
    .line 293
    .line 294
    move-result v3

    .line 295
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 296
    .line 297
    .line 298
    invoke-virtual {v2, v7}, Landroid/graphics/RenderNode;->setOutline(Landroid/graphics/Outline;)Z

    .line 299
    .line 300
    .line 301
    iput-boolean v6, v1, Lh3/d;->g:Z

    .line 302
    .line 303
    invoke-virtual {v1}, Lh3/d;->a()V

    .line 304
    .line 305
    .line 306
    :cond_c
    :goto_3
    iput-boolean v4, v0, Lh3/c;->g:Z

    .line 307
    .line 308
    return-void
.end method

.method public final b()V
    .locals 15

    .line 1
    iget-boolean v0, p0, Lh3/c;->s:Z

    .line 2
    .line 3
    if-eqz v0, :cond_6

    .line 4
    .line 5
    iget v0, p0, Lh3/c;->q:I

    .line 6
    .line 7
    if-nez v0, :cond_6

    .line 8
    .line 9
    iget-object v0, p0, Lh3/c;->r:Lvv0/d;

    .line 10
    .line 11
    iget-object v1, v0, Lvv0/d;->b:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Lh3/c;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {v1}, Lh3/c;->f()V

    .line 18
    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    iput-object v1, v0, Lvv0/d;->b:Ljava/lang/Object;

    .line 22
    .line 23
    :cond_0
    iget-object v0, v0, Lvv0/d;->d:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Landroidx/collection/r0;

    .line 26
    .line 27
    if-eqz v0, :cond_5

    .line 28
    .line 29
    iget-object v1, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 30
    .line 31
    iget-object v2, v0, Landroidx/collection/r0;->a:[J

    .line 32
    .line 33
    array-length v3, v2

    .line 34
    add-int/lit8 v3, v3, -0x2

    .line 35
    .line 36
    if-ltz v3, :cond_4

    .line 37
    .line 38
    const/4 v4, 0x0

    .line 39
    move v5, v4

    .line 40
    :goto_0
    aget-wide v6, v2, v5

    .line 41
    .line 42
    not-long v8, v6

    .line 43
    const/4 v10, 0x7

    .line 44
    shl-long/2addr v8, v10

    .line 45
    and-long/2addr v8, v6

    .line 46
    const-wide v10, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    and-long/2addr v8, v10

    .line 52
    cmp-long v8, v8, v10

    .line 53
    .line 54
    if-eqz v8, :cond_3

    .line 55
    .line 56
    sub-int v8, v5, v3

    .line 57
    .line 58
    not-int v8, v8

    .line 59
    ushr-int/lit8 v8, v8, 0x1f

    .line 60
    .line 61
    const/16 v9, 0x8

    .line 62
    .line 63
    rsub-int/lit8 v8, v8, 0x8

    .line 64
    .line 65
    move v10, v4

    .line 66
    :goto_1
    if-ge v10, v8, :cond_2

    .line 67
    .line 68
    const-wide/16 v11, 0xff

    .line 69
    .line 70
    and-long/2addr v11, v6

    .line 71
    const-wide/16 v13, 0x80

    .line 72
    .line 73
    cmp-long v11, v11, v13

    .line 74
    .line 75
    if-gez v11, :cond_1

    .line 76
    .line 77
    shl-int/lit8 v11, v5, 0x3

    .line 78
    .line 79
    add-int/2addr v11, v10

    .line 80
    aget-object v11, v1, v11

    .line 81
    .line 82
    check-cast v11, Lh3/c;

    .line 83
    .line 84
    invoke-virtual {v11}, Lh3/c;->f()V

    .line 85
    .line 86
    .line 87
    :cond_1
    shr-long/2addr v6, v9

    .line 88
    add-int/lit8 v10, v10, 0x1

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    if-ne v8, v9, :cond_4

    .line 92
    .line 93
    :cond_3
    if-eq v5, v3, :cond_4

    .line 94
    .line 95
    add-int/lit8 v5, v5, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_4
    invoke-virtual {v0}, Landroidx/collection/r0;->b()V

    .line 99
    .line 100
    .line 101
    :cond_5
    iget-object p0, p0, Lh3/c;->a:Lh3/d;

    .line 102
    .line 103
    iget-object p0, p0, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 104
    .line 105
    invoke-virtual {p0}, Landroid/graphics/RenderNode;->discardDisplayList()V

    .line 106
    .line 107
    .line 108
    :cond_6
    return-void
.end method

.method public final c(Le3/r;Lh3/c;)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    iget-object v4, v1, Lh3/c;->a:Lh3/d;

    .line 8
    .line 9
    iget-object v5, v4, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 10
    .line 11
    iget-boolean v0, v1, Lh3/c;->s:Z

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    goto/16 :goto_a

    .line 16
    .line 17
    :cond_0
    invoke-virtual {v1}, Lh3/c;->a()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v5}, Landroid/graphics/RenderNode;->hasDisplayList()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    :try_start_0
    iget-object v0, v1, Lh3/c;->b:Lt4/c;

    .line 27
    .line 28
    iget-object v6, v1, Lh3/c;->c:Lt4/m;

    .line 29
    .line 30
    iget-object v7, v1, Lh3/c;->e:La3/f;

    .line 31
    .line 32
    iget-object v8, v4, Lh3/d;->b:Lg3/b;

    .line 33
    .line 34
    iget-object v9, v4, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 35
    .line 36
    invoke-virtual {v9}, Landroid/graphics/RenderNode;->beginRecording()Landroid/graphics/RecordingCanvas;

    .line 37
    .line 38
    .line 39
    move-result-object v10
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 40
    :try_start_1
    iget-object v11, v4, Lh3/d;->a:Laq/a;

    .line 41
    .line 42
    iget-object v12, v11, Laq/a;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v12, Le3/a;

    .line 45
    .line 46
    iget-object v13, v12, Le3/a;->a:Landroid/graphics/Canvas;

    .line 47
    .line 48
    iput-object v10, v12, Le3/a;->a:Landroid/graphics/Canvas;

    .line 49
    .line 50
    iget-object v10, v8, Lg3/b;->e:Lgw0/c;

    .line 51
    .line 52
    invoke-virtual {v10, v0}, Lgw0/c;->z(Lt4/c;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v10, v6}, Lgw0/c;->A(Lt4/m;)V

    .line 56
    .line 57
    .line 58
    iput-object v1, v10, Lgw0/c;->f:Ljava/lang/Object;

    .line 59
    .line 60
    iget-wide v14, v4, Lh3/d;->d:J

    .line 61
    .line 62
    invoke-virtual {v10, v14, v15}, Lgw0/c;->B(J)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v10, v12}, Lgw0/c;->x(Le3/r;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v7, v8}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    iget-object v0, v11, Laq/a;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Le3/a;

    .line 74
    .line 75
    iput-object v13, v0, Le3/a;->a:Landroid/graphics/Canvas;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 76
    .line 77
    :try_start_2
    invoke-virtual {v9}, Landroid/graphics/RenderNode;->endRecording()V

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :catchall_0
    move-exception v0

    .line 82
    invoke-virtual {v9}, Landroid/graphics/RenderNode;->endRecording()V

    .line 83
    .line 84
    .line 85
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 86
    :catchall_1
    :cond_1
    :goto_0
    iget v0, v4, Lh3/d;->n:F

    .line 87
    .line 88
    const/4 v6, 0x0

    .line 89
    cmpl-float v0, v0, v6

    .line 90
    .line 91
    if-lez v0, :cond_2

    .line 92
    .line 93
    const/4 v0, 0x1

    .line 94
    goto :goto_1

    .line 95
    :cond_2
    const/4 v0, 0x0

    .line 96
    :goto_1
    if-eqz v0, :cond_3

    .line 97
    .line 98
    invoke-interface {v2}, Le3/r;->k()V

    .line 99
    .line 100
    .line 101
    :cond_3
    invoke-static {v2}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    invoke-virtual {v8}, Landroid/graphics/Canvas;->isHardwareAccelerated()Z

    .line 106
    .line 107
    .line 108
    move-result v14

    .line 109
    if-nez v14, :cond_8

    .line 110
    .line 111
    iget-wide v9, v1, Lh3/c;->t:J

    .line 112
    .line 113
    const/16 v11, 0x20

    .line 114
    .line 115
    shr-long v12, v9, v11

    .line 116
    .line 117
    long-to-int v12, v12

    .line 118
    int-to-float v12, v12

    .line 119
    const-wide v16, 0xffffffffL

    .line 120
    .line 121
    .line 122
    .line 123
    .line 124
    and-long v9, v9, v16

    .line 125
    .line 126
    long-to-int v9, v9

    .line 127
    int-to-float v10, v9

    .line 128
    move-object v9, v8

    .line 129
    iget-wide v7, v1, Lh3/c;->u:J

    .line 130
    .line 131
    move-wide/from16 v20, v7

    .line 132
    .line 133
    shr-long v6, v20, v11

    .line 134
    .line 135
    long-to-int v6, v6

    .line 136
    int-to-float v6, v6

    .line 137
    add-float v11, v12, v6

    .line 138
    .line 139
    and-long v6, v20, v16

    .line 140
    .line 141
    long-to-int v6, v6

    .line 142
    int-to-float v6, v6

    .line 143
    add-float/2addr v6, v10

    .line 144
    iget v7, v4, Lh3/d;->h:F

    .line 145
    .line 146
    iget v8, v4, Lh3/d;->i:I

    .line 147
    .line 148
    const/high16 v13, 0x3f800000    # 1.0f

    .line 149
    .line 150
    cmpg-float v13, v7, v13

    .line 151
    .line 152
    if-ltz v13, :cond_5

    .line 153
    .line 154
    const/4 v13, 0x3

    .line 155
    if-ne v8, v13, :cond_5

    .line 156
    .line 157
    iget v13, v4, Lh3/d;->y:I

    .line 158
    .line 159
    const/4 v15, 0x1

    .line 160
    if-ne v13, v15, :cond_4

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_4
    invoke-virtual {v9}, Landroid/graphics/Canvas;->save()I

    .line 164
    .line 165
    .line 166
    move-object v8, v9

    .line 167
    move v9, v12

    .line 168
    goto :goto_3

    .line 169
    :cond_5
    :goto_2
    iget-object v13, v1, Lh3/c;->p:Le3/g;

    .line 170
    .line 171
    if-nez v13, :cond_6

    .line 172
    .line 173
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 174
    .line 175
    .line 176
    move-result-object v13

    .line 177
    iput-object v13, v1, Lh3/c;->p:Le3/g;

    .line 178
    .line 179
    :cond_6
    invoke-virtual {v13, v7}, Le3/g;->c(F)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v13, v8}, Le3/g;->d(I)V

    .line 183
    .line 184
    .line 185
    const/4 v7, 0x0

    .line 186
    invoke-virtual {v13, v7}, Le3/g;->f(Le3/m;)V

    .line 187
    .line 188
    .line 189
    iget-object v13, v13, Le3/g;->a:Landroid/graphics/Paint;

    .line 190
    .line 191
    move-object v8, v9

    .line 192
    move v9, v12

    .line 193
    move v12, v6

    .line 194
    invoke-virtual/range {v8 .. v13}, Landroid/graphics/Canvas;->saveLayer(FFFFLandroid/graphics/Paint;)I

    .line 195
    .line 196
    .line 197
    :goto_3
    invoke-virtual {v8, v9, v10}, Landroid/graphics/Canvas;->translate(FF)V

    .line 198
    .line 199
    .line 200
    iget-object v6, v4, Lh3/d;->f:Landroid/graphics/Matrix;

    .line 201
    .line 202
    if-nez v6, :cond_7

    .line 203
    .line 204
    new-instance v6, Landroid/graphics/Matrix;

    .line 205
    .line 206
    invoke-direct {v6}, Landroid/graphics/Matrix;-><init>()V

    .line 207
    .line 208
    .line 209
    iput-object v6, v4, Lh3/d;->f:Landroid/graphics/Matrix;

    .line 210
    .line 211
    :cond_7
    invoke-virtual {v5, v6}, Landroid/graphics/RenderNode;->getMatrix(Landroid/graphics/Matrix;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v8, v6}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 215
    .line 216
    .line 217
    :cond_8
    if-nez v14, :cond_9

    .line 218
    .line 219
    iget-boolean v4, v1, Lh3/c;->w:Z

    .line 220
    .line 221
    if-eqz v4, :cond_9

    .line 222
    .line 223
    const/4 v15, 0x1

    .line 224
    goto :goto_4

    .line 225
    :cond_9
    const/4 v15, 0x0

    .line 226
    :goto_4
    if-eqz v15, :cond_e

    .line 227
    .line 228
    invoke-interface {v2}, Le3/r;->o()V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v1}, Lh3/c;->e()Le3/g0;

    .line 232
    .line 233
    .line 234
    move-result-object v4

    .line 235
    instance-of v6, v4, Le3/e0;

    .line 236
    .line 237
    if-eqz v6, :cond_a

    .line 238
    .line 239
    check-cast v4, Le3/e0;

    .line 240
    .line 241
    iget-object v4, v4, Le3/e0;->a:Ld3/c;

    .line 242
    .line 243
    invoke-static {v2, v4}, Le3/r;->d(Le3/r;Ld3/c;)V

    .line 244
    .line 245
    .line 246
    goto :goto_6

    .line 247
    :cond_a
    instance-of v6, v4, Le3/f0;

    .line 248
    .line 249
    if-eqz v6, :cond_c

    .line 250
    .line 251
    iget-object v6, v1, Lh3/c;->m:Le3/i;

    .line 252
    .line 253
    if-eqz v6, :cond_b

    .line 254
    .line 255
    invoke-virtual {v6}, Le3/i;->k()V

    .line 256
    .line 257
    .line 258
    goto :goto_5

    .line 259
    :cond_b
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 260
    .line 261
    .line 262
    move-result-object v6

    .line 263
    iput-object v6, v1, Lh3/c;->m:Le3/i;

    .line 264
    .line 265
    :goto_5
    check-cast v4, Le3/f0;

    .line 266
    .line 267
    iget-object v4, v4, Le3/f0;->a:Ld3/d;

    .line 268
    .line 269
    invoke-static {v6, v4}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 270
    .line 271
    .line 272
    const/4 v7, 0x1

    .line 273
    invoke-interface {v2, v6, v7}, Le3/r;->e(Le3/i;I)V

    .line 274
    .line 275
    .line 276
    goto :goto_6

    .line 277
    :cond_c
    const/4 v7, 0x1

    .line 278
    instance-of v6, v4, Le3/d0;

    .line 279
    .line 280
    if-eqz v6, :cond_d

    .line 281
    .line 282
    check-cast v4, Le3/d0;

    .line 283
    .line 284
    iget-object v4, v4, Le3/d0;->a:Le3/i;

    .line 285
    .line 286
    invoke-interface {v2, v4, v7}, Le3/r;->e(Le3/i;I)V

    .line 287
    .line 288
    .line 289
    goto :goto_6

    .line 290
    :cond_d
    new-instance v0, La8/r0;

    .line 291
    .line 292
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 293
    .line 294
    .line 295
    throw v0

    .line 296
    :cond_e
    :goto_6
    if-eqz v3, :cond_14

    .line 297
    .line 298
    iget-object v3, v3, Lh3/c;->r:Lvv0/d;

    .line 299
    .line 300
    iget-boolean v4, v3, Lvv0/d;->a:Z

    .line 301
    .line 302
    if-nez v4, :cond_f

    .line 303
    .line 304
    const-string v4, "Only add dependencies during a tracking"

    .line 305
    .line 306
    invoke-static {v4}, Le3/a0;->a(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    :cond_f
    iget-object v4, v3, Lvv0/d;->d:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v4, Landroidx/collection/r0;

    .line 312
    .line 313
    if-eqz v4, :cond_10

    .line 314
    .line 315
    invoke-virtual {v4, v1}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    goto :goto_7

    .line 319
    :cond_10
    iget-object v4, v3, Lvv0/d;->b:Ljava/lang/Object;

    .line 320
    .line 321
    check-cast v4, Lh3/c;

    .line 322
    .line 323
    if-eqz v4, :cond_11

    .line 324
    .line 325
    sget-object v4, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 326
    .line 327
    new-instance v4, Landroidx/collection/r0;

    .line 328
    .line 329
    invoke-direct {v4}, Landroidx/collection/r0;-><init>()V

    .line 330
    .line 331
    .line 332
    iget-object v6, v3, Lvv0/d;->b:Ljava/lang/Object;

    .line 333
    .line 334
    check-cast v6, Lh3/c;

    .line 335
    .line 336
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v4, v6}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    invoke-virtual {v4, v1}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 343
    .line 344
    .line 345
    iput-object v4, v3, Lvv0/d;->d:Ljava/lang/Object;

    .line 346
    .line 347
    const/4 v7, 0x0

    .line 348
    iput-object v7, v3, Lvv0/d;->b:Ljava/lang/Object;

    .line 349
    .line 350
    goto :goto_7

    .line 351
    :cond_11
    iput-object v1, v3, Lvv0/d;->b:Ljava/lang/Object;

    .line 352
    .line 353
    :goto_7
    iget-object v4, v3, Lvv0/d;->e:Ljava/lang/Object;

    .line 354
    .line 355
    check-cast v4, Landroidx/collection/r0;

    .line 356
    .line 357
    if-eqz v4, :cond_12

    .line 358
    .line 359
    invoke-virtual {v4, v1}, Landroidx/collection/r0;->l(Ljava/lang/Object;)Z

    .line 360
    .line 361
    .line 362
    move-result v3

    .line 363
    const/16 v19, 0x1

    .line 364
    .line 365
    xor-int/lit8 v7, v3, 0x1

    .line 366
    .line 367
    goto :goto_8

    .line 368
    :cond_12
    const/16 v19, 0x1

    .line 369
    .line 370
    iget-object v4, v3, Lvv0/d;->c:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast v4, Lh3/c;

    .line 373
    .line 374
    if-eq v4, v1, :cond_13

    .line 375
    .line 376
    move/from16 v7, v19

    .line 377
    .line 378
    goto :goto_8

    .line 379
    :cond_13
    const/4 v7, 0x0

    .line 380
    iput-object v7, v3, Lvv0/d;->c:Ljava/lang/Object;

    .line 381
    .line 382
    const/4 v7, 0x0

    .line 383
    :goto_8
    if-eqz v7, :cond_14

    .line 384
    .line 385
    iget v3, v1, Lh3/c;->q:I

    .line 386
    .line 387
    add-int/lit8 v3, v3, 0x1

    .line 388
    .line 389
    iput v3, v1, Lh3/c;->q:I

    .line 390
    .line 391
    :cond_14
    invoke-static {v2}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 392
    .line 393
    .line 394
    move-result-object v3

    .line 395
    invoke-virtual {v3}, Landroid/graphics/Canvas;->isHardwareAccelerated()Z

    .line 396
    .line 397
    .line 398
    move-result v3

    .line 399
    if-nez v3, :cond_16

    .line 400
    .line 401
    iget-object v3, v1, Lh3/c;->o:Lg3/b;

    .line 402
    .line 403
    if-nez v3, :cond_15

    .line 404
    .line 405
    new-instance v3, Lg3/b;

    .line 406
    .line 407
    invoke-direct {v3}, Lg3/b;-><init>()V

    .line 408
    .line 409
    .line 410
    iput-object v3, v1, Lh3/c;->o:Lg3/b;

    .line 411
    .line 412
    :cond_15
    iget-object v4, v3, Lg3/b;->e:Lgw0/c;

    .line 413
    .line 414
    iget-object v5, v1, Lh3/c;->b:Lt4/c;

    .line 415
    .line 416
    iget-object v6, v1, Lh3/c;->c:Lt4/m;

    .line 417
    .line 418
    iget-wide v9, v1, Lh3/c;->u:J

    .line 419
    .line 420
    invoke-static {v9, v10}, Lkp/f9;->c(J)J

    .line 421
    .line 422
    .line 423
    move-result-wide v9

    .line 424
    invoke-virtual {v4}, Lgw0/c;->k()Lt4/c;

    .line 425
    .line 426
    .line 427
    move-result-object v7

    .line 428
    invoke-virtual {v4}, Lgw0/c;->l()Lt4/m;

    .line 429
    .line 430
    .line 431
    move-result-object v11

    .line 432
    invoke-virtual {v4}, Lgw0/c;->h()Le3/r;

    .line 433
    .line 434
    .line 435
    move-result-object v12

    .line 436
    move/from16 v16, v14

    .line 437
    .line 438
    invoke-virtual {v4}, Lgw0/c;->o()J

    .line 439
    .line 440
    .line 441
    move-result-wide v13

    .line 442
    move/from16 v17, v0

    .line 443
    .line 444
    iget-object v0, v4, Lgw0/c;->f:Ljava/lang/Object;

    .line 445
    .line 446
    move-object/from16 v18, v8

    .line 447
    .line 448
    move-object v8, v0

    .line 449
    check-cast v8, Lh3/c;

    .line 450
    .line 451
    invoke-virtual {v4, v5}, Lgw0/c;->z(Lt4/c;)V

    .line 452
    .line 453
    .line 454
    invoke-virtual {v4, v6}, Lgw0/c;->A(Lt4/m;)V

    .line 455
    .line 456
    .line 457
    invoke-virtual {v4, v2}, Lgw0/c;->x(Le3/r;)V

    .line 458
    .line 459
    .line 460
    invoke-virtual {v4, v9, v10}, Lgw0/c;->B(J)V

    .line 461
    .line 462
    .line 463
    iput-object v1, v4, Lgw0/c;->f:Ljava/lang/Object;

    .line 464
    .line 465
    invoke-interface {v2}, Le3/r;->o()V

    .line 466
    .line 467
    .line 468
    :try_start_3
    invoke-virtual {v1, v3}, Lh3/c;->d(Lg3/d;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 469
    .line 470
    .line 471
    invoke-interface {v2}, Le3/r;->i()V

    .line 472
    .line 473
    .line 474
    invoke-virtual {v4, v7}, Lgw0/c;->z(Lt4/c;)V

    .line 475
    .line 476
    .line 477
    invoke-virtual {v4, v11}, Lgw0/c;->A(Lt4/m;)V

    .line 478
    .line 479
    .line 480
    invoke-virtual {v4, v12}, Lgw0/c;->x(Le3/r;)V

    .line 481
    .line 482
    .line 483
    invoke-virtual {v4, v13, v14}, Lgw0/c;->B(J)V

    .line 484
    .line 485
    .line 486
    iput-object v8, v4, Lgw0/c;->f:Ljava/lang/Object;

    .line 487
    .line 488
    goto :goto_9

    .line 489
    :catchall_2
    move-exception v0

    .line 490
    invoke-interface {v2}, Le3/r;->i()V

    .line 491
    .line 492
    .line 493
    invoke-virtual {v4, v7}, Lgw0/c;->z(Lt4/c;)V

    .line 494
    .line 495
    .line 496
    invoke-virtual {v4, v11}, Lgw0/c;->A(Lt4/m;)V

    .line 497
    .line 498
    .line 499
    invoke-virtual {v4, v12}, Lgw0/c;->x(Le3/r;)V

    .line 500
    .line 501
    .line 502
    invoke-virtual {v4, v13, v14}, Lgw0/c;->B(J)V

    .line 503
    .line 504
    .line 505
    iput-object v8, v4, Lgw0/c;->f:Ljava/lang/Object;

    .line 506
    .line 507
    throw v0

    .line 508
    :cond_16
    move/from16 v17, v0

    .line 509
    .line 510
    move-object/from16 v18, v8

    .line 511
    .line 512
    move/from16 v16, v14

    .line 513
    .line 514
    invoke-static {v2}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 515
    .line 516
    .line 517
    move-result-object v0

    .line 518
    invoke-virtual {v0, v5}, Landroid/graphics/Canvas;->drawRenderNode(Landroid/graphics/RenderNode;)V

    .line 519
    .line 520
    .line 521
    :goto_9
    if-eqz v15, :cond_17

    .line 522
    .line 523
    invoke-interface {v2}, Le3/r;->i()V

    .line 524
    .line 525
    .line 526
    :cond_17
    if-eqz v17, :cond_18

    .line 527
    .line 528
    invoke-interface {v2}, Le3/r;->p()V

    .line 529
    .line 530
    .line 531
    :cond_18
    if-nez v16, :cond_19

    .line 532
    .line 533
    invoke-virtual/range {v18 .. v18}, Landroid/graphics/Canvas;->restore()V

    .line 534
    .line 535
    .line 536
    :cond_19
    :goto_a
    return-void
.end method

.method public final d(Lg3/d;)V
    .locals 13

    .line 1
    iget-object v0, p0, Lh3/c;->r:Lvv0/d;

    .line 2
    .line 3
    iget-object v1, v0, Lvv0/d;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lh3/c;

    .line 6
    .line 7
    iput-object v1, v0, Lvv0/d;->c:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v1, v0, Lvv0/d;->d:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Landroidx/collection/r0;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    invoke-virtual {v1}, Landroidx/collection/r0;->h()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    iget-object v2, v0, Lvv0/d;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Landroidx/collection/r0;

    .line 24
    .line 25
    if-nez v2, :cond_0

    .line 26
    .line 27
    sget-object v2, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 28
    .line 29
    new-instance v2, Landroidx/collection/r0;

    .line 30
    .line 31
    invoke-direct {v2}, Landroidx/collection/r0;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v2, v0, Lvv0/d;->e:Ljava/lang/Object;

    .line 35
    .line 36
    :cond_0
    invoke-virtual {v2, v1}, Landroidx/collection/r0;->j(Landroidx/collection/r0;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1}, Landroidx/collection/r0;->b()V

    .line 40
    .line 41
    .line 42
    :cond_1
    const/4 v1, 0x1

    .line 43
    iput-boolean v1, v0, Lvv0/d;->a:Z

    .line 44
    .line 45
    iget-object p0, p0, Lh3/c;->d:Lay0/k;

    .line 46
    .line 47
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    const/4 p0, 0x0

    .line 51
    iput-boolean p0, v0, Lvv0/d;->a:Z

    .line 52
    .line 53
    iget-object p1, v0, Lvv0/d;->c:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p1, Lh3/c;

    .line 56
    .line 57
    if-eqz p1, :cond_2

    .line 58
    .line 59
    invoke-virtual {p1}, Lh3/c;->f()V

    .line 60
    .line 61
    .line 62
    :cond_2
    iget-object p1, v0, Lvv0/d;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p1, Landroidx/collection/r0;

    .line 65
    .line 66
    if-eqz p1, :cond_7

    .line 67
    .line 68
    invoke-virtual {p1}, Landroidx/collection/r0;->h()Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-eqz v0, :cond_7

    .line 73
    .line 74
    iget-object v0, p1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 75
    .line 76
    iget-object v1, p1, Landroidx/collection/r0;->a:[J

    .line 77
    .line 78
    array-length v2, v1

    .line 79
    add-int/lit8 v2, v2, -0x2

    .line 80
    .line 81
    if-ltz v2, :cond_6

    .line 82
    .line 83
    move v3, p0

    .line 84
    :goto_0
    aget-wide v4, v1, v3

    .line 85
    .line 86
    not-long v6, v4

    .line 87
    const/4 v8, 0x7

    .line 88
    shl-long/2addr v6, v8

    .line 89
    and-long/2addr v6, v4

    .line 90
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 91
    .line 92
    .line 93
    .line 94
    .line 95
    and-long/2addr v6, v8

    .line 96
    cmp-long v6, v6, v8

    .line 97
    .line 98
    if-eqz v6, :cond_5

    .line 99
    .line 100
    sub-int v6, v3, v2

    .line 101
    .line 102
    not-int v6, v6

    .line 103
    ushr-int/lit8 v6, v6, 0x1f

    .line 104
    .line 105
    const/16 v7, 0x8

    .line 106
    .line 107
    rsub-int/lit8 v6, v6, 0x8

    .line 108
    .line 109
    move v8, p0

    .line 110
    :goto_1
    if-ge v8, v6, :cond_4

    .line 111
    .line 112
    const-wide/16 v9, 0xff

    .line 113
    .line 114
    and-long/2addr v9, v4

    .line 115
    const-wide/16 v11, 0x80

    .line 116
    .line 117
    cmp-long v9, v9, v11

    .line 118
    .line 119
    if-gez v9, :cond_3

    .line 120
    .line 121
    shl-int/lit8 v9, v3, 0x3

    .line 122
    .line 123
    add-int/2addr v9, v8

    .line 124
    aget-object v9, v0, v9

    .line 125
    .line 126
    check-cast v9, Lh3/c;

    .line 127
    .line 128
    invoke-virtual {v9}, Lh3/c;->f()V

    .line 129
    .line 130
    .line 131
    :cond_3
    shr-long/2addr v4, v7

    .line 132
    add-int/lit8 v8, v8, 0x1

    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_4
    if-ne v6, v7, :cond_6

    .line 136
    .line 137
    :cond_5
    if-eq v3, v2, :cond_6

    .line 138
    .line 139
    add-int/lit8 v3, v3, 0x1

    .line 140
    .line 141
    goto :goto_0

    .line 142
    :cond_6
    invoke-virtual {p1}, Landroidx/collection/r0;->b()V

    .line 143
    .line 144
    .line 145
    :cond_7
    return-void
.end method

.method public final e()Le3/g0;
    .locals 14

    .line 1
    iget-object v0, p0, Lh3/c;->k:Le3/g0;

    .line 2
    .line 3
    iget-object v1, p0, Lh3/c;->l:Le3/i;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-object v0

    .line 8
    :cond_0
    if-eqz v1, :cond_1

    .line 9
    .line 10
    new-instance v0, Le3/d0;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Le3/d0;-><init>(Le3/i;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lh3/c;->k:Le3/g0;

    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_1
    iget-wide v0, p0, Lh3/c;->u:J

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkp/f9;->c(J)J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    iget-wide v2, p0, Lh3/c;->h:J

    .line 25
    .line 26
    iget-wide v4, p0, Lh3/c;->i:J

    .line 27
    .line 28
    const-wide v6, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    cmp-long v6, v4, v6

    .line 34
    .line 35
    if-nez v6, :cond_2

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    move-wide v0, v4

    .line 39
    :goto_0
    const/16 v4, 0x20

    .line 40
    .line 41
    shr-long v5, v2, v4

    .line 42
    .line 43
    long-to-int v5, v5

    .line 44
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 45
    .line 46
    .line 47
    move-result v8

    .line 48
    const-wide v5, 0xffffffffL

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    and-long/2addr v2, v5

    .line 54
    long-to-int v2, v2

    .line 55
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 56
    .line 57
    .line 58
    move-result v9

    .line 59
    shr-long v2, v0, v4

    .line 60
    .line 61
    long-to-int v2, v2

    .line 62
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    add-float v10, v2, v8

    .line 67
    .line 68
    and-long/2addr v0, v5

    .line 69
    long-to-int v0, v0

    .line 70
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    add-float v11, v0, v9

    .line 75
    .line 76
    iget v0, p0, Lh3/c;->j:F

    .line 77
    .line 78
    const/4 v1, 0x0

    .line 79
    cmpl-float v1, v0, v1

    .line 80
    .line 81
    if-lez v1, :cond_3

    .line 82
    .line 83
    new-instance v1, Le3/f0;

    .line 84
    .line 85
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    int-to-long v2, v2

    .line 90
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    int-to-long v12, v0

    .line 95
    shl-long/2addr v2, v4

    .line 96
    and-long v4, v12, v5

    .line 97
    .line 98
    or-long v6, v2, v4

    .line 99
    .line 100
    invoke-static/range {v6 .. v11}, Ljp/df;->c(JFFFF)Ld3/d;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-direct {v1, v0}, Le3/f0;-><init>(Ld3/d;)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    new-instance v1, Le3/e0;

    .line 109
    .line 110
    new-instance v0, Ld3/c;

    .line 111
    .line 112
    invoke-direct {v0, v8, v9, v10, v11}, Ld3/c;-><init>(FFFF)V

    .line 113
    .line 114
    .line 115
    invoke-direct {v1, v0}, Le3/e0;-><init>(Ld3/c;)V

    .line 116
    .line 117
    .line 118
    :goto_1
    iput-object v1, p0, Lh3/c;->k:Le3/g0;

    .line 119
    .line 120
    return-object v1
.end method

.method public final f()V
    .locals 1

    .line 1
    iget v0, p0, Lh3/c;->q:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Lh3/c;->q:I

    .line 6
    .line 7
    invoke-virtual {p0}, Lh3/c;->b()V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final g(Lt4/c;Lt4/m;JLay0/k;)V
    .locals 9

    .line 1
    iget-wide v0, p0, Lh3/c;->u:J

    .line 2
    .line 3
    invoke-static {v0, v1, p3, p4}, Lt4/l;->a(JJ)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lh3/c;->a:Lh3/d;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iput-wide p3, p0, Lh3/c;->u:J

    .line 12
    .line 13
    iget-wide v2, p0, Lh3/c;->t:J

    .line 14
    .line 15
    const/16 v0, 0x20

    .line 16
    .line 17
    shr-long v4, v2, v0

    .line 18
    .line 19
    long-to-int v4, v4

    .line 20
    const-wide v5, 0xffffffffL

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    and-long/2addr v2, v5

    .line 26
    long-to-int v2, v2

    .line 27
    iget-object v3, v1, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 28
    .line 29
    shr-long v7, p3, v0

    .line 30
    .line 31
    long-to-int v0, v7

    .line 32
    add-int/2addr v0, v4

    .line 33
    and-long/2addr v5, p3

    .line 34
    long-to-int v5, v5

    .line 35
    add-int/2addr v5, v2

    .line 36
    invoke-virtual {v3, v4, v2, v0, v5}, Landroid/graphics/RenderNode;->setPosition(IIII)Z

    .line 37
    .line 38
    .line 39
    invoke-static {p3, p4}, Lkp/f9;->c(J)J

    .line 40
    .line 41
    .line 42
    move-result-wide p3

    .line 43
    iput-wide p3, v1, Lh3/d;->d:J

    .line 44
    .line 45
    iget-wide p3, p0, Lh3/c;->i:J

    .line 46
    .line 47
    const-wide v2, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    cmp-long p3, p3, v2

    .line 53
    .line 54
    if-nez p3, :cond_0

    .line 55
    .line 56
    const/4 p3, 0x1

    .line 57
    iput-boolean p3, p0, Lh3/c;->g:Z

    .line 58
    .line 59
    invoke-virtual {p0}, Lh3/c;->a()V

    .line 60
    .line 61
    .line 62
    :cond_0
    iput-object p1, p0, Lh3/c;->b:Lt4/c;

    .line 63
    .line 64
    iput-object p2, p0, Lh3/c;->c:Lt4/m;

    .line 65
    .line 66
    iput-object p5, p0, Lh3/c;->d:Lay0/k;

    .line 67
    .line 68
    iget-object p3, p0, Lh3/c;->e:La3/f;

    .line 69
    .line 70
    iget-object p4, v1, Lh3/d;->b:Lg3/b;

    .line 71
    .line 72
    iget-object p5, v1, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 73
    .line 74
    invoke-virtual {p5}, Landroid/graphics/RenderNode;->beginRecording()Landroid/graphics/RecordingCanvas;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    :try_start_0
    iget-object v2, v1, Lh3/d;->a:Laq/a;

    .line 79
    .line 80
    iget-object v3, v2, Laq/a;->e:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v3, Le3/a;

    .line 83
    .line 84
    iget-object v4, v3, Le3/a;->a:Landroid/graphics/Canvas;

    .line 85
    .line 86
    iput-object v0, v3, Le3/a;->a:Landroid/graphics/Canvas;

    .line 87
    .line 88
    iget-object v0, p4, Lg3/b;->e:Lgw0/c;

    .line 89
    .line 90
    invoke-virtual {v0, p1}, Lgw0/c;->z(Lt4/c;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0, p2}, Lgw0/c;->A(Lt4/m;)V

    .line 94
    .line 95
    .line 96
    iput-object p0, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 97
    .line 98
    iget-wide p0, v1, Lh3/d;->d:J

    .line 99
    .line 100
    invoke-virtual {v0, p0, p1}, Lgw0/c;->B(J)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, v3}, Lgw0/c;->x(Le3/r;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p3, p4}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    iget-object p0, v2, Laq/a;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p0, Le3/a;

    .line 112
    .line 113
    iput-object v4, p0, Le3/a;->a:Landroid/graphics/Canvas;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 114
    .line 115
    invoke-virtual {p5}, Landroid/graphics/RenderNode;->endRecording()V

    .line 116
    .line 117
    .line 118
    return-void

    .line 119
    :catchall_0
    move-exception p0

    .line 120
    invoke-virtual {p5}, Landroid/graphics/RenderNode;->endRecording()V

    .line 121
    .line 122
    .line 123
    throw p0
.end method

.method public final h(F)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh3/c;->a:Lh3/d;

    .line 2
    .line 3
    iget v0, p0, Lh3/d;->h:F

    .line 4
    .line 5
    cmpg-float v0, v0, p1

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    iput p1, p0, Lh3/d;->h:F

    .line 11
    .line 12
    iget-object p0, p0, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Landroid/graphics/RenderNode;->setAlpha(F)Z

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final i(JJF)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lh3/c;->h:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Ld3/b;->c(JJ)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-wide v0, p0, Lh3/c;->i:J

    .line 10
    .line 11
    invoke-static {v0, v1, p3, p4}, Ld3/e;->a(JJ)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    iget v0, p0, Lh3/c;->j:F

    .line 18
    .line 19
    cmpg-float v0, v0, p5

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    iget-object v0, p0, Lh3/c;->l:Le3/i;

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    return-void

    .line 29
    :cond_1
    :goto_0
    const/4 v0, 0x0

    .line 30
    iput-object v0, p0, Lh3/c;->k:Le3/g0;

    .line 31
    .line 32
    iput-object v0, p0, Lh3/c;->l:Le3/i;

    .line 33
    .line 34
    const/4 v0, 0x1

    .line 35
    iput-boolean v0, p0, Lh3/c;->g:Z

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    iput-boolean v0, p0, Lh3/c;->n:Z

    .line 39
    .line 40
    iput-wide p1, p0, Lh3/c;->h:J

    .line 41
    .line 42
    iput-wide p3, p0, Lh3/c;->i:J

    .line 43
    .line 44
    iput p5, p0, Lh3/c;->j:F

    .line 45
    .line 46
    invoke-virtual {p0}, Lh3/c;->a()V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final j(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lh3/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lh3/b;

    .line 7
    .line 8
    iget v1, v0, Lh3/b;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lh3/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh3/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lh3/b;-><init>(Lh3/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lh3/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh3/b;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lh3/b;->f:I

    .line 52
    .line 53
    sget-object p1, Lh3/c;->y:Lh3/e;

    .line 54
    .line 55
    invoke-interface {p1, p0, v0}, Lh3/e;->a(Lh3/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    check-cast p1, Landroid/graphics/Bitmap;

    .line 63
    .line 64
    new-instance p0, Le3/f;

    .line 65
    .line 66
    invoke-direct {p0, p1}, Le3/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 67
    .line 68
    .line 69
    return-object p0
.end method

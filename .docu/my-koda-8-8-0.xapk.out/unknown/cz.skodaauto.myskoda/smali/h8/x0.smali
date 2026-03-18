.class public final Lh8/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/i0;


# instance fields
.field public A:Z

.field public B:Z

.field public final a:Lh8/v0;

.field public final b:Lcom/google/crypto/tink/shaded/protobuf/d;

.field public final c:Lbb/g0;

.field public final d:Ld8/j;

.field public final e:Ld8/f;

.field public f:Lh8/r0;

.field public g:Lt7/o;

.field public h:Laq/a;

.field public i:I

.field public j:[J

.field public k:[J

.field public l:[I

.field public m:[I

.field public n:[J

.field public o:[Lo8/h0;

.field public p:I

.field public q:I

.field public r:I

.field public s:I

.field public t:J

.field public u:J

.field public v:J

.field public w:Z

.field public x:Z

.field public y:Z

.field public z:Lt7/o;


# direct methods
.method public constructor <init>(Lk8/e;Ld8/j;Ld8/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lh8/x0;->d:Ld8/j;

    .line 5
    .line 6
    iput-object p3, p0, Lh8/x0;->e:Ld8/f;

    .line 7
    .line 8
    new-instance p2, Lh8/v0;

    .line 9
    .line 10
    invoke-direct {p2, p1}, Lh8/v0;-><init>(Lk8/e;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lh8/x0;->a:Lh8/v0;

    .line 14
    .line 15
    new-instance p1, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 16
    .line 17
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lh8/x0;->b:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 21
    .line 22
    const/16 p1, 0x3e8

    .line 23
    .line 24
    iput p1, p0, Lh8/x0;->i:I

    .line 25
    .line 26
    new-array p2, p1, [J

    .line 27
    .line 28
    iput-object p2, p0, Lh8/x0;->j:[J

    .line 29
    .line 30
    new-array p2, p1, [J

    .line 31
    .line 32
    iput-object p2, p0, Lh8/x0;->k:[J

    .line 33
    .line 34
    new-array p2, p1, [J

    .line 35
    .line 36
    iput-object p2, p0, Lh8/x0;->n:[J

    .line 37
    .line 38
    new-array p2, p1, [I

    .line 39
    .line 40
    iput-object p2, p0, Lh8/x0;->m:[I

    .line 41
    .line 42
    new-array p2, p1, [I

    .line 43
    .line 44
    iput-object p2, p0, Lh8/x0;->l:[I

    .line 45
    .line 46
    new-array p1, p1, [Lo8/h0;

    .line 47
    .line 48
    iput-object p1, p0, Lh8/x0;->o:[Lo8/h0;

    .line 49
    .line 50
    new-instance p1, Lbb/g0;

    .line 51
    .line 52
    new-instance p2, Lf3/d;

    .line 53
    .line 54
    const/16 p3, 0xb

    .line 55
    .line 56
    invoke-direct {p2, p3}, Lf3/d;-><init>(I)V

    .line 57
    .line 58
    .line 59
    invoke-direct {p1, p2}, Lbb/g0;-><init>(Lf3/d;)V

    .line 60
    .line 61
    .line 62
    iput-object p1, p0, Lh8/x0;->c:Lbb/g0;

    .line 63
    .line 64
    const-wide/high16 p1, -0x8000000000000000L

    .line 65
    .line 66
    iput-wide p1, p0, Lh8/x0;->t:J

    .line 67
    .line 68
    iput-wide p1, p0, Lh8/x0;->u:J

    .line 69
    .line 70
    iput-wide p1, p0, Lh8/x0;->v:J

    .line 71
    .line 72
    const/4 p1, 0x1

    .line 73
    iput-boolean p1, p0, Lh8/x0;->y:Z

    .line 74
    .line 75
    iput-boolean p1, p0, Lh8/x0;->x:Z

    .line 76
    .line 77
    iput-boolean p1, p0, Lh8/x0;->A:Z

    .line 78
    .line 79
    return-void
.end method


# virtual methods
.method public final a(Lw7/p;II)V
    .locals 8

    .line 1
    :cond_0
    :goto_0
    iget-object p3, p0, Lh8/x0;->a:Lh8/v0;

    .line 2
    .line 3
    if-lez p2, :cond_1

    .line 4
    .line 5
    invoke-virtual {p3, p2}, Lh8/v0;->b(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p3, Lh8/v0;->f:Lc1/i2;

    .line 10
    .line 11
    iget-object v2, v1, Lc1/i2;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Lk8/a;

    .line 14
    .line 15
    iget-object v3, v2, Lk8/a;->a:[B

    .line 16
    .line 17
    iget-wide v4, p3, Lh8/v0;->g:J

    .line 18
    .line 19
    iget-wide v6, v1, Lc1/i2;->d:J

    .line 20
    .line 21
    sub-long/2addr v4, v6

    .line 22
    long-to-int v1, v4

    .line 23
    iget v2, v2, Lk8/a;->b:I

    .line 24
    .line 25
    add-int/2addr v1, v2

    .line 26
    invoke-virtual {p1, v3, v1, v0}, Lw7/p;->h([BII)V

    .line 27
    .line 28
    .line 29
    sub-int/2addr p2, v0

    .line 30
    iget-wide v1, p3, Lh8/v0;->g:J

    .line 31
    .line 32
    int-to-long v3, v0

    .line 33
    add-long/2addr v1, v3

    .line 34
    iput-wide v1, p3, Lh8/v0;->g:J

    .line 35
    .line 36
    iget-object v0, p3, Lh8/v0;->f:Lc1/i2;

    .line 37
    .line 38
    iget-wide v3, v0, Lc1/i2;->e:J

    .line 39
    .line 40
    cmp-long v1, v1, v3

    .line 41
    .line 42
    if-nez v1, :cond_0

    .line 43
    .line 44
    iget-object v0, v0, Lc1/i2;->g:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Lc1/i2;

    .line 47
    .line 48
    iput-object v0, p3, Lh8/v0;->f:Lc1/i2;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final b(JIIILo8/h0;)V
    .locals 9

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move v3, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v3, v1

    .line 10
    :goto_0
    iget-boolean v4, p0, Lh8/x0;->x:Z

    .line 11
    .line 12
    if-eqz v4, :cond_2

    .line 13
    .line 14
    if-nez v3, :cond_1

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    iput-boolean v1, p0, Lh8/x0;->x:Z

    .line 18
    .line 19
    :cond_2
    iget-boolean v3, p0, Lh8/x0;->A:Z

    .line 20
    .line 21
    if-eqz v3, :cond_5

    .line 22
    .line 23
    iget-wide v3, p0, Lh8/x0;->t:J

    .line 24
    .line 25
    cmp-long v3, p1, v3

    .line 26
    .line 27
    if-gez v3, :cond_3

    .line 28
    .line 29
    :goto_1
    return-void

    .line 30
    :cond_3
    if-nez v0, :cond_5

    .line 31
    .line 32
    iget-boolean v0, p0, Lh8/x0;->B:Z

    .line 33
    .line 34
    if-nez v0, :cond_4

    .line 35
    .line 36
    const-string v0, "SampleQueue"

    .line 37
    .line 38
    new-instance v3, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v4, "Overriding unexpected non-sync sample for format: "

    .line 41
    .line 42
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    iget-object v4, p0, Lh8/x0;->z:Lt7/o;

    .line 46
    .line 47
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-static {v0, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iput-boolean v2, p0, Lh8/x0;->B:Z

    .line 58
    .line 59
    :cond_4
    or-int/lit8 p3, p3, 0x1

    .line 60
    .line 61
    :cond_5
    iget-object v0, p0, Lh8/x0;->a:Lh8/v0;

    .line 62
    .line 63
    iget-wide v3, v0, Lh8/v0;->g:J

    .line 64
    .line 65
    int-to-long v5, p4

    .line 66
    sub-long/2addr v3, v5

    .line 67
    int-to-long v5, p5

    .line 68
    sub-long/2addr v3, v5

    .line 69
    monitor-enter p0

    .line 70
    :try_start_0
    iget p5, p0, Lh8/x0;->p:I

    .line 71
    .line 72
    if-lez p5, :cond_7

    .line 73
    .line 74
    sub-int/2addr p5, v2

    .line 75
    invoke-virtual {p0, p5}, Lh8/x0;->h(I)I

    .line 76
    .line 77
    .line 78
    move-result p5

    .line 79
    iget-object v0, p0, Lh8/x0;->k:[J

    .line 80
    .line 81
    aget-wide v5, v0, p5

    .line 82
    .line 83
    iget-object v0, p0, Lh8/x0;->l:[I

    .line 84
    .line 85
    aget p5, v0, p5

    .line 86
    .line 87
    int-to-long v7, p5

    .line 88
    add-long/2addr v5, v7

    .line 89
    cmp-long p5, v5, v3

    .line 90
    .line 91
    if-gtz p5, :cond_6

    .line 92
    .line 93
    move p5, v2

    .line 94
    goto :goto_2

    .line 95
    :cond_6
    move p5, v1

    .line 96
    :goto_2
    invoke-static {p5}, Lw7/a;->c(Z)V

    .line 97
    .line 98
    .line 99
    goto :goto_3

    .line 100
    :catchall_0
    move-exception p1

    .line 101
    goto/16 :goto_9

    .line 102
    .line 103
    :cond_7
    :goto_3
    const/high16 p5, 0x20000000

    .line 104
    .line 105
    and-int/2addr p5, p3

    .line 106
    if-eqz p5, :cond_8

    .line 107
    .line 108
    move p5, v2

    .line 109
    goto :goto_4

    .line 110
    :cond_8
    move p5, v1

    .line 111
    :goto_4
    iput-boolean p5, p0, Lh8/x0;->w:Z

    .line 112
    .line 113
    iget-wide v5, p0, Lh8/x0;->v:J

    .line 114
    .line 115
    invoke-static {v5, v6, p1, p2}, Ljava/lang/Math;->max(JJ)J

    .line 116
    .line 117
    .line 118
    move-result-wide v5

    .line 119
    iput-wide v5, p0, Lh8/x0;->v:J

    .line 120
    .line 121
    iget p5, p0, Lh8/x0;->p:I

    .line 122
    .line 123
    invoke-virtual {p0, p5}, Lh8/x0;->h(I)I

    .line 124
    .line 125
    .line 126
    move-result p5

    .line 127
    iget-object v0, p0, Lh8/x0;->n:[J

    .line 128
    .line 129
    aput-wide p1, v0, p5

    .line 130
    .line 131
    iget-object p1, p0, Lh8/x0;->k:[J

    .line 132
    .line 133
    aput-wide v3, p1, p5

    .line 134
    .line 135
    iget-object p1, p0, Lh8/x0;->l:[I

    .line 136
    .line 137
    aput p4, p1, p5

    .line 138
    .line 139
    iget-object p1, p0, Lh8/x0;->m:[I

    .line 140
    .line 141
    aput p3, p1, p5

    .line 142
    .line 143
    iget-object p1, p0, Lh8/x0;->o:[Lo8/h0;

    .line 144
    .line 145
    aput-object p6, p1, p5

    .line 146
    .line 147
    iget-object p1, p0, Lh8/x0;->j:[J

    .line 148
    .line 149
    const-wide/16 p2, 0x0

    .line 150
    .line 151
    aput-wide p2, p1, p5

    .line 152
    .line 153
    iget-object p1, p0, Lh8/x0;->c:Lbb/g0;

    .line 154
    .line 155
    iget-object p1, p1, Lbb/g0;->f:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast p1, Landroid/util/SparseArray;

    .line 158
    .line 159
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 160
    .line 161
    .line 162
    move-result p1

    .line 163
    if-nez p1, :cond_9

    .line 164
    .line 165
    move p1, v2

    .line 166
    goto :goto_5

    .line 167
    :cond_9
    move p1, v1

    .line 168
    :goto_5
    if-nez p1, :cond_a

    .line 169
    .line 170
    iget-object p1, p0, Lh8/x0;->c:Lbb/g0;

    .line 171
    .line 172
    iget-object p1, p1, Lbb/g0;->f:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast p1, Landroid/util/SparseArray;

    .line 175
    .line 176
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 177
    .line 178
    .line 179
    move-result p2

    .line 180
    sub-int/2addr p2, v2

    .line 181
    invoke-virtual {p1, p2}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    check-cast p1, Lh8/w0;

    .line 186
    .line 187
    iget-object p1, p1, Lh8/w0;->a:Lt7/o;

    .line 188
    .line 189
    iget-object p2, p0, Lh8/x0;->z:Lt7/o;

    .line 190
    .line 191
    invoke-virtual {p1, p2}, Lt7/o;->equals(Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result p1

    .line 195
    if-nez p1, :cond_10

    .line 196
    .line 197
    :cond_a
    iget-object p1, p0, Lh8/x0;->z:Lt7/o;

    .line 198
    .line 199
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 200
    .line 201
    .line 202
    iget-object p2, p0, Lh8/x0;->d:Ld8/j;

    .line 203
    .line 204
    if-eqz p2, :cond_b

    .line 205
    .line 206
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 207
    .line 208
    .line 209
    sget-object p2, Ld8/i;->a:Ld8/i;

    .line 210
    .line 211
    goto :goto_6

    .line 212
    :cond_b
    sget-object p2, Ld8/i;->a:Ld8/i;

    .line 213
    .line 214
    :goto_6
    iget-object p3, p0, Lh8/x0;->c:Lbb/g0;

    .line 215
    .line 216
    iget p4, p0, Lh8/x0;->q:I

    .line 217
    .line 218
    iget p5, p0, Lh8/x0;->p:I

    .line 219
    .line 220
    add-int/2addr p4, p5

    .line 221
    new-instance p5, Lh8/w0;

    .line 222
    .line 223
    invoke-direct {p5, p1, p2}, Lh8/w0;-><init>(Lt7/o;Ld8/i;)V

    .line 224
    .line 225
    .line 226
    iget-object p1, p3, Lbb/g0;->f:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast p1, Landroid/util/SparseArray;

    .line 229
    .line 230
    iget p2, p3, Lbb/g0;->e:I

    .line 231
    .line 232
    const/4 p6, -0x1

    .line 233
    if-ne p2, p6, :cond_d

    .line 234
    .line 235
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 236
    .line 237
    .line 238
    move-result p2

    .line 239
    if-nez p2, :cond_c

    .line 240
    .line 241
    move p2, v2

    .line 242
    goto :goto_7

    .line 243
    :cond_c
    move p2, v1

    .line 244
    :goto_7
    invoke-static {p2}, Lw7/a;->j(Z)V

    .line 245
    .line 246
    .line 247
    iput v1, p3, Lbb/g0;->e:I

    .line 248
    .line 249
    :cond_d
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 250
    .line 251
    .line 252
    move-result p2

    .line 253
    if-lez p2, :cond_f

    .line 254
    .line 255
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 256
    .line 257
    .line 258
    move-result p2

    .line 259
    sub-int/2addr p2, v2

    .line 260
    invoke-virtual {p1, p2}, Landroid/util/SparseArray;->keyAt(I)I

    .line 261
    .line 262
    .line 263
    move-result p2

    .line 264
    if-lt p4, p2, :cond_e

    .line 265
    .line 266
    move p6, v2

    .line 267
    goto :goto_8

    .line 268
    :cond_e
    move p6, v1

    .line 269
    :goto_8
    invoke-static {p6}, Lw7/a;->c(Z)V

    .line 270
    .line 271
    .line 272
    if-ne p2, p4, :cond_f

    .line 273
    .line 274
    iget-object p2, p3, Lbb/g0;->g:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast p2, Lf3/d;

    .line 277
    .line 278
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 279
    .line 280
    .line 281
    move-result p3

    .line 282
    sub-int/2addr p3, v2

    .line 283
    invoke-virtual {p1, p3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object p3

    .line 287
    invoke-virtual {p2, p3}, Lf3/d;->accept(Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    :cond_f
    invoke-virtual {p1, p4, p5}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    :cond_10
    iget p1, p0, Lh8/x0;->p:I

    .line 294
    .line 295
    add-int/2addr p1, v2

    .line 296
    iput p1, p0, Lh8/x0;->p:I

    .line 297
    .line 298
    iget p2, p0, Lh8/x0;->i:I

    .line 299
    .line 300
    if-ne p1, p2, :cond_11

    .line 301
    .line 302
    add-int/lit16 p1, p2, 0x3e8

    .line 303
    .line 304
    new-array p3, p1, [J

    .line 305
    .line 306
    new-array p4, p1, [J

    .line 307
    .line 308
    new-array p5, p1, [J

    .line 309
    .line 310
    new-array p6, p1, [I

    .line 311
    .line 312
    new-array v0, p1, [I

    .line 313
    .line 314
    new-array v2, p1, [Lo8/h0;

    .line 315
    .line 316
    iget v3, p0, Lh8/x0;->r:I

    .line 317
    .line 318
    sub-int/2addr p2, v3

    .line 319
    iget-object v4, p0, Lh8/x0;->k:[J

    .line 320
    .line 321
    invoke-static {v4, v3, p4, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 322
    .line 323
    .line 324
    iget-object v3, p0, Lh8/x0;->n:[J

    .line 325
    .line 326
    iget v4, p0, Lh8/x0;->r:I

    .line 327
    .line 328
    invoke-static {v3, v4, p5, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 329
    .line 330
    .line 331
    iget-object v3, p0, Lh8/x0;->m:[I

    .line 332
    .line 333
    iget v4, p0, Lh8/x0;->r:I

    .line 334
    .line 335
    invoke-static {v3, v4, p6, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 336
    .line 337
    .line 338
    iget-object v3, p0, Lh8/x0;->l:[I

    .line 339
    .line 340
    iget v4, p0, Lh8/x0;->r:I

    .line 341
    .line 342
    invoke-static {v3, v4, v0, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 343
    .line 344
    .line 345
    iget-object v3, p0, Lh8/x0;->o:[Lo8/h0;

    .line 346
    .line 347
    iget v4, p0, Lh8/x0;->r:I

    .line 348
    .line 349
    invoke-static {v3, v4, v2, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 350
    .line 351
    .line 352
    iget-object v3, p0, Lh8/x0;->j:[J

    .line 353
    .line 354
    iget v4, p0, Lh8/x0;->r:I

    .line 355
    .line 356
    invoke-static {v3, v4, p3, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 357
    .line 358
    .line 359
    iget v3, p0, Lh8/x0;->r:I

    .line 360
    .line 361
    iget-object v4, p0, Lh8/x0;->k:[J

    .line 362
    .line 363
    invoke-static {v4, v1, p4, p2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 364
    .line 365
    .line 366
    iget-object v4, p0, Lh8/x0;->n:[J

    .line 367
    .line 368
    invoke-static {v4, v1, p5, p2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 369
    .line 370
    .line 371
    iget-object v4, p0, Lh8/x0;->m:[I

    .line 372
    .line 373
    invoke-static {v4, v1, p6, p2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 374
    .line 375
    .line 376
    iget-object v4, p0, Lh8/x0;->l:[I

    .line 377
    .line 378
    invoke-static {v4, v1, v0, p2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 379
    .line 380
    .line 381
    iget-object v4, p0, Lh8/x0;->o:[Lo8/h0;

    .line 382
    .line 383
    invoke-static {v4, v1, v2, p2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 384
    .line 385
    .line 386
    iget-object v4, p0, Lh8/x0;->j:[J

    .line 387
    .line 388
    invoke-static {v4, v1, p3, p2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 389
    .line 390
    .line 391
    iput-object p4, p0, Lh8/x0;->k:[J

    .line 392
    .line 393
    iput-object p5, p0, Lh8/x0;->n:[J

    .line 394
    .line 395
    iput-object p6, p0, Lh8/x0;->m:[I

    .line 396
    .line 397
    iput-object v0, p0, Lh8/x0;->l:[I

    .line 398
    .line 399
    iput-object v2, p0, Lh8/x0;->o:[Lo8/h0;

    .line 400
    .line 401
    iput-object p3, p0, Lh8/x0;->j:[J

    .line 402
    .line 403
    iput v1, p0, Lh8/x0;->r:I

    .line 404
    .line 405
    iput p1, p0, Lh8/x0;->i:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 406
    .line 407
    :cond_11
    monitor-exit p0

    .line 408
    return-void

    .line 409
    :goto_9
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 410
    throw p1
.end method

.method public final c(Lt7/o;)V
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    const/4 v0, 0x0

    .line 3
    :try_start_0
    iput-boolean v0, p0, Lh8/x0;->y:Z

    .line 4
    .line 5
    iget-object v1, p0, Lh8/x0;->z:Lt7/o;

    .line 6
    .line 7
    invoke-static {p1, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    monitor-exit p0

    .line 14
    goto :goto_2

    .line 15
    :cond_0
    :try_start_1
    iget-object v1, p0, Lh8/x0;->c:Lbb/g0;

    .line 16
    .line 17
    iget-object v1, v1, Lbb/g0;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Landroid/util/SparseArray;

    .line 20
    .line 21
    invoke-virtual {v1}, Landroid/util/SparseArray;->size()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v2, 0x1

    .line 26
    if-nez v1, :cond_1

    .line 27
    .line 28
    move v1, v2

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    move v1, v0

    .line 31
    :goto_0
    if-nez v1, :cond_2

    .line 32
    .line 33
    iget-object v1, p0, Lh8/x0;->c:Lbb/g0;

    .line 34
    .line 35
    iget-object v1, v1, Lbb/g0;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Landroid/util/SparseArray;

    .line 38
    .line 39
    invoke-virtual {v1}, Landroid/util/SparseArray;->size()I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    sub-int/2addr v3, v2

    .line 44
    invoke-virtual {v1, v3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Lh8/w0;

    .line 49
    .line 50
    iget-object v1, v1, Lh8/w0;->a:Lt7/o;

    .line 51
    .line 52
    invoke-virtual {v1, p1}, Lt7/o;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_2

    .line 57
    .line 58
    iget-object p1, p0, Lh8/x0;->c:Lbb/g0;

    .line 59
    .line 60
    iget-object p1, p1, Lbb/g0;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p1, Landroid/util/SparseArray;

    .line 63
    .line 64
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    sub-int/2addr v1, v2

    .line 69
    invoke-virtual {p1, v1}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    check-cast p1, Lh8/w0;

    .line 74
    .line 75
    iget-object p1, p1, Lh8/w0;->a:Lt7/o;

    .line 76
    .line 77
    iput-object p1, p0, Lh8/x0;->z:Lt7/o;

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :catchall_0
    move-exception p1

    .line 81
    goto :goto_3

    .line 82
    :cond_2
    iput-object p1, p0, Lh8/x0;->z:Lt7/o;

    .line 83
    .line 84
    :goto_1
    iget-boolean p1, p0, Lh8/x0;->A:Z

    .line 85
    .line 86
    iget-object v1, p0, Lh8/x0;->z:Lt7/o;

    .line 87
    .line 88
    iget-object v3, v1, Lt7/o;->n:Ljava/lang/String;

    .line 89
    .line 90
    iget-object v1, v1, Lt7/o;->k:Ljava/lang/String;

    .line 91
    .line 92
    invoke-static {v3, v1}, Lt7/d0;->a(Ljava/lang/String;Ljava/lang/String;)Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    and-int/2addr p1, v1

    .line 97
    iput-boolean p1, p0, Lh8/x0;->A:Z

    .line 98
    .line 99
    iput-boolean v0, p0, Lh8/x0;->B:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 100
    .line 101
    monitor-exit p0

    .line 102
    move v0, v2

    .line 103
    :goto_2
    iget-object p0, p0, Lh8/x0;->f:Lh8/r0;

    .line 104
    .line 105
    if-eqz p0, :cond_3

    .line 106
    .line 107
    if-eqz v0, :cond_3

    .line 108
    .line 109
    iget-object p1, p0, Lh8/r0;->t:Landroid/os/Handler;

    .line 110
    .line 111
    iget-object p0, p0, Lh8/r0;->r:Lh8/m0;

    .line 112
    .line 113
    invoke-virtual {p1, p0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 114
    .line 115
    .line 116
    :cond_3
    return-void

    .line 117
    :goto_3
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 118
    throw p1
.end method

.method public final d(Lt7/g;IZ)I
    .locals 7

    .line 1
    iget-object p0, p0, Lh8/x0;->a:Lh8/v0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lh8/v0;->b(I)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    iget-object v0, p0, Lh8/v0;->f:Lc1/i2;

    .line 8
    .line 9
    iget-object v1, v0, Lc1/i2;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Lk8/a;

    .line 12
    .line 13
    iget-object v2, v1, Lk8/a;->a:[B

    .line 14
    .line 15
    iget-wide v3, p0, Lh8/v0;->g:J

    .line 16
    .line 17
    iget-wide v5, v0, Lc1/i2;->d:J

    .line 18
    .line 19
    sub-long/2addr v3, v5

    .line 20
    long-to-int v0, v3

    .line 21
    iget v1, v1, Lk8/a;->b:I

    .line 22
    .line 23
    add-int/2addr v0, v1

    .line 24
    invoke-interface {p1, v2, v0, p2}, Lt7/g;->read([BII)I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    const/4 p2, -0x1

    .line 29
    if-ne p1, p2, :cond_1

    .line 30
    .line 31
    if-eqz p3, :cond_0

    .line 32
    .line 33
    return p2

    .line 34
    :cond_0
    new-instance p0, Ljava/io/EOFException;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    iget-wide p2, p0, Lh8/v0;->g:J

    .line 41
    .line 42
    int-to-long v0, p1

    .line 43
    add-long/2addr p2, v0

    .line 44
    iput-wide p2, p0, Lh8/v0;->g:J

    .line 45
    .line 46
    iget-object v0, p0, Lh8/v0;->f:Lc1/i2;

    .line 47
    .line 48
    iget-wide v1, v0, Lc1/i2;->e:J

    .line 49
    .line 50
    cmp-long p2, p2, v1

    .line 51
    .line 52
    if-nez p2, :cond_2

    .line 53
    .line 54
    iget-object p2, v0, Lc1/i2;->g:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p2, Lc1/i2;

    .line 57
    .line 58
    iput-object p2, p0, Lh8/v0;->f:Lc1/i2;

    .line 59
    .line 60
    :cond_2
    return p1
.end method

.method public final e(I)J
    .locals 8

    .line 1
    iget-wide v0, p0, Lh8/x0;->u:J

    .line 2
    .line 3
    const-wide/high16 v2, -0x8000000000000000L

    .line 4
    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    add-int/lit8 v4, p1, -0x1

    .line 9
    .line 10
    invoke-virtual {p0, v4}, Lh8/x0;->h(I)I

    .line 11
    .line 12
    .line 13
    move-result v4

    .line 14
    const/4 v5, 0x0

    .line 15
    :goto_0
    if-ge v5, p1, :cond_3

    .line 16
    .line 17
    iget-object v6, p0, Lh8/x0;->n:[J

    .line 18
    .line 19
    aget-wide v6, v6, v4

    .line 20
    .line 21
    invoke-static {v2, v3, v6, v7}, Ljava/lang/Math;->max(JJ)J

    .line 22
    .line 23
    .line 24
    move-result-wide v2

    .line 25
    iget-object v6, p0, Lh8/x0;->m:[I

    .line 26
    .line 27
    aget v6, v6, v4

    .line 28
    .line 29
    and-int/lit8 v6, v6, 0x1

    .line 30
    .line 31
    if-eqz v6, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    add-int/lit8 v4, v4, -0x1

    .line 35
    .line 36
    const/4 v6, -0x1

    .line 37
    if-ne v4, v6, :cond_2

    .line 38
    .line 39
    iget v4, p0, Lh8/x0;->i:I

    .line 40
    .line 41
    add-int/lit8 v4, v4, -0x1

    .line 42
    .line 43
    :cond_2
    add-int/lit8 v5, v5, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_3
    :goto_1
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->max(JJ)J

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    iput-wide v0, p0, Lh8/x0;->u:J

    .line 51
    .line 52
    iget v0, p0, Lh8/x0;->p:I

    .line 53
    .line 54
    sub-int/2addr v0, p1

    .line 55
    iput v0, p0, Lh8/x0;->p:I

    .line 56
    .line 57
    iget v0, p0, Lh8/x0;->q:I

    .line 58
    .line 59
    add-int/2addr v0, p1

    .line 60
    iput v0, p0, Lh8/x0;->q:I

    .line 61
    .line 62
    iget v1, p0, Lh8/x0;->r:I

    .line 63
    .line 64
    add-int/2addr v1, p1

    .line 65
    iput v1, p0, Lh8/x0;->r:I

    .line 66
    .line 67
    iget v2, p0, Lh8/x0;->i:I

    .line 68
    .line 69
    if-lt v1, v2, :cond_4

    .line 70
    .line 71
    sub-int/2addr v1, v2

    .line 72
    iput v1, p0, Lh8/x0;->r:I

    .line 73
    .line 74
    :cond_4
    iget v1, p0, Lh8/x0;->s:I

    .line 75
    .line 76
    sub-int/2addr v1, p1

    .line 77
    iput v1, p0, Lh8/x0;->s:I

    .line 78
    .line 79
    const/4 p1, 0x0

    .line 80
    if-gez v1, :cond_5

    .line 81
    .line 82
    iput p1, p0, Lh8/x0;->s:I

    .line 83
    .line 84
    :cond_5
    iget-object v1, p0, Lh8/x0;->c:Lbb/g0;

    .line 85
    .line 86
    iget-object v2, v1, Lbb/g0;->f:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v2, Landroid/util/SparseArray;

    .line 89
    .line 90
    :goto_2
    invoke-virtual {v2}, Landroid/util/SparseArray;->size()I

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    add-int/lit8 v3, v3, -0x1

    .line 95
    .line 96
    if-ge p1, v3, :cond_7

    .line 97
    .line 98
    add-int/lit8 v3, p1, 0x1

    .line 99
    .line 100
    invoke-virtual {v2, v3}, Landroid/util/SparseArray;->keyAt(I)I

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    if-lt v0, v4, :cond_7

    .line 105
    .line 106
    iget-object v4, v1, Lbb/g0;->g:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v4, Lf3/d;

    .line 109
    .line 110
    invoke-virtual {v2, p1}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    invoke-virtual {v4, v5}, Lf3/d;->accept(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v2, p1}, Landroid/util/SparseArray;->removeAt(I)V

    .line 118
    .line 119
    .line 120
    iget p1, v1, Lbb/g0;->e:I

    .line 121
    .line 122
    if-lez p1, :cond_6

    .line 123
    .line 124
    add-int/lit8 p1, p1, -0x1

    .line 125
    .line 126
    iput p1, v1, Lbb/g0;->e:I

    .line 127
    .line 128
    :cond_6
    move p1, v3

    .line 129
    goto :goto_2

    .line 130
    :cond_7
    iget p1, p0, Lh8/x0;->p:I

    .line 131
    .line 132
    if-nez p1, :cond_9

    .line 133
    .line 134
    iget p1, p0, Lh8/x0;->r:I

    .line 135
    .line 136
    if-nez p1, :cond_8

    .line 137
    .line 138
    iget p1, p0, Lh8/x0;->i:I

    .line 139
    .line 140
    :cond_8
    add-int/lit8 p1, p1, -0x1

    .line 141
    .line 142
    iget-object v0, p0, Lh8/x0;->k:[J

    .line 143
    .line 144
    aget-wide v0, v0, p1

    .line 145
    .line 146
    iget-object p0, p0, Lh8/x0;->l:[I

    .line 147
    .line 148
    aget p0, p0, p1

    .line 149
    .line 150
    int-to-long p0, p0

    .line 151
    add-long/2addr v0, p0

    .line 152
    return-wide v0

    .line 153
    :cond_9
    iget-object p1, p0, Lh8/x0;->k:[J

    .line 154
    .line 155
    iget p0, p0, Lh8/x0;->r:I

    .line 156
    .line 157
    aget-wide p0, p1, p0

    .line 158
    .line 159
    return-wide p0
.end method

.method public final f()V
    .locals 3

    .line 1
    iget-object v0, p0, Lh8/x0;->a:Lh8/v0;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget v1, p0, Lh8/x0;->p:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    monitor-exit p0

    .line 9
    const-wide/16 v1, -0x1

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    :try_start_1
    invoke-virtual {p0, v1}, Lh8/x0;->e(I)J

    .line 13
    .line 14
    .line 15
    move-result-wide v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 16
    monitor-exit p0

    .line 17
    :goto_0
    invoke-virtual {v0, v1, v2}, Lh8/v0;->a(J)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception v0

    .line 22
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 23
    throw v0
.end method

.method public final g(JIIZ)I
    .locals 5

    .line 1
    const/4 v0, -0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v2, v1

    .line 4
    :goto_0
    if-ge v2, p4, :cond_4

    .line 5
    .line 6
    iget-object v3, p0, Lh8/x0;->n:[J

    .line 7
    .line 8
    aget-wide v3, v3, p3

    .line 9
    .line 10
    cmp-long v3, v3, p1

    .line 11
    .line 12
    if-gtz v3, :cond_4

    .line 13
    .line 14
    if-eqz p5, :cond_0

    .line 15
    .line 16
    iget-object v4, p0, Lh8/x0;->m:[I

    .line 17
    .line 18
    aget v4, v4, p3

    .line 19
    .line 20
    and-int/lit8 v4, v4, 0x1

    .line 21
    .line 22
    if-eqz v4, :cond_2

    .line 23
    .line 24
    :cond_0
    if-nez v3, :cond_1

    .line 25
    .line 26
    return v2

    .line 27
    :cond_1
    move v0, v2

    .line 28
    :cond_2
    add-int/lit8 p3, p3, 0x1

    .line 29
    .line 30
    iget v3, p0, Lh8/x0;->i:I

    .line 31
    .line 32
    if-ne p3, v3, :cond_3

    .line 33
    .line 34
    move p3, v1

    .line 35
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_4
    return v0
.end method

.method public final h(I)I
    .locals 1

    .line 1
    iget v0, p0, Lh8/x0;->r:I

    .line 2
    .line 3
    add-int/2addr v0, p1

    .line 4
    iget p0, p0, Lh8/x0;->i:I

    .line 5
    .line 6
    if-ge v0, p0, :cond_0

    .line 7
    .line 8
    return v0

    .line 9
    :cond_0
    sub-int/2addr v0, p0

    .line 10
    return v0
.end method

.method public final declared-synchronized i(Z)Z
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget v0, p0, Lh8/x0;->s:I

    .line 3
    .line 4
    iget v1, p0, Lh8/x0;->p:I

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x1

    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    move v1, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v1, v2

    .line 13
    :goto_0
    if-nez v1, :cond_3

    .line 14
    .line 15
    if-nez p1, :cond_1

    .line 16
    .line 17
    iget-boolean p1, p0, Lh8/x0;->w:Z

    .line 18
    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    iget-object p1, p0, Lh8/x0;->z:Lt7/o;

    .line 22
    .line 23
    if-eqz p1, :cond_2

    .line 24
    .line 25
    iget-object v0, p0, Lh8/x0;->g:Lt7/o;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    if-eq p1, v0, :cond_2

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :catchall_0
    move-exception p1

    .line 31
    goto :goto_2

    .line 32
    :cond_1
    :goto_1
    move v2, v3

    .line 33
    :cond_2
    monitor-exit p0

    .line 34
    return v2

    .line 35
    :cond_3
    :try_start_1
    iget-object p1, p0, Lh8/x0;->c:Lbb/g0;

    .line 36
    .line 37
    iget v1, p0, Lh8/x0;->q:I

    .line 38
    .line 39
    add-int/2addr v1, v0

    .line 40
    invoke-virtual {p1, v1}, Lbb/g0;->g(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    check-cast p1, Lh8/w0;

    .line 45
    .line 46
    iget-object p1, p1, Lh8/w0;->a:Lt7/o;

    .line 47
    .line 48
    iget-object v0, p0, Lh8/x0;->g:Lt7/o;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 49
    .line 50
    if-eq p1, v0, :cond_4

    .line 51
    .line 52
    monitor-exit p0

    .line 53
    return v3

    .line 54
    :cond_4
    :try_start_2
    iget p1, p0, Lh8/x0;->s:I

    .line 55
    .line 56
    invoke-virtual {p0, p1}, Lh8/x0;->h(I)I

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    invoke-virtual {p0, p1}, Lh8/x0;->j(I)Z

    .line 61
    .line 62
    .line 63
    move-result p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 64
    monitor-exit p0

    .line 65
    return p1

    .line 66
    :goto_2
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 67
    throw p1
.end method

.method public final j(I)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lh8/x0;->h:Laq/a;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {v0}, Laq/a;->w()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x4

    .line 10
    if-eq v0, v1, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Lh8/x0;->m:[I

    .line 13
    .line 14
    aget p1, v0, p1

    .line 15
    .line 16
    const/high16 v0, 0x40000000    # 2.0f

    .line 17
    .line 18
    and-int/2addr p1, v0

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lh8/x0;->h:Laq/a;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_1
    const/4 p0, 0x1

    .line 29
    return p0
.end method

.method public final k(Lt7/o;Lb81/d;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lh8/x0;->g:Lt7/o;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v1, 0x0

    .line 8
    :goto_0
    if-nez v0, :cond_1

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    goto :goto_1

    .line 12
    :cond_1
    iget-object v0, v0, Lt7/o;->r:Lt7/k;

    .line 13
    .line 14
    :goto_1
    iput-object p1, p0, Lh8/x0;->g:Lt7/o;

    .line 15
    .line 16
    iget-object v2, p1, Lt7/o;->r:Lt7/k;

    .line 17
    .line 18
    iget-object v3, p0, Lh8/x0;->d:Ld8/j;

    .line 19
    .line 20
    if-eqz v3, :cond_2

    .line 21
    .line 22
    invoke-interface {v3, p1}, Ld8/j;->c(Lt7/o;)I

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    invoke-virtual {p1}, Lt7/o;->a()Lt7/n;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    iput v4, v5, Lt7/n;->N:I

    .line 31
    .line 32
    new-instance v4, Lt7/o;

    .line 33
    .line 34
    invoke-direct {v4, v5}, Lt7/o;-><init>(Lt7/n;)V

    .line 35
    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    move-object v4, p1

    .line 39
    :goto_2
    iput-object v4, p2, Lb81/d;->f:Ljava/lang/Object;

    .line 40
    .line 41
    iget-object v4, p0, Lh8/x0;->h:Laq/a;

    .line 42
    .line 43
    iput-object v4, p2, Lb81/d;->e:Ljava/lang/Object;

    .line 44
    .line 45
    if-nez v3, :cond_3

    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_3
    if-nez v1, :cond_4

    .line 49
    .line 50
    invoke-static {v0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_4

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_4
    iget-object v0, p0, Lh8/x0;->h:Laq/a;

    .line 58
    .line 59
    iget-object v1, p0, Lh8/x0;->e:Ld8/f;

    .line 60
    .line 61
    invoke-interface {v3, v1, p1}, Ld8/j;->f(Ld8/f;Lt7/o;)Laq/a;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    iput-object p1, p0, Lh8/x0;->h:Laq/a;

    .line 66
    .line 67
    iput-object p1, p2, Lb81/d;->e:Ljava/lang/Object;

    .line 68
    .line 69
    if-eqz v0, :cond_5

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Laq/a;->E(Ld8/f;)V

    .line 72
    .line 73
    .line 74
    :cond_5
    :goto_3
    return-void
.end method

.method public final l(Z)V
    .locals 11

    .line 1
    iget-object v0, p0, Lh8/x0;->a:Lh8/v0;

    .line 2
    .line 3
    iget-object v1, v0, Lh8/v0;->d:Lc1/i2;

    .line 4
    .line 5
    iget-object v2, v1, Lc1/i2;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lk8/a;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x1

    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_0
    iget-object v2, v0, Lh8/v0;->a:Lk8/e;

    .line 15
    .line 16
    monitor-enter v2

    .line 17
    move-object v5, v1

    .line 18
    :cond_1
    :goto_0
    if-eqz v5, :cond_3

    .line 19
    .line 20
    :try_start_0
    iget-object v6, v2, Lk8/e;->f:[Lk8/a;

    .line 21
    .line 22
    iget v7, v2, Lk8/e;->e:I

    .line 23
    .line 24
    add-int/lit8 v8, v7, 0x1

    .line 25
    .line 26
    iput v8, v2, Lk8/e;->e:I

    .line 27
    .line 28
    iget-object v8, v5, Lc1/i2;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v8, Lk8/a;

    .line 31
    .line 32
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    aput-object v8, v6, v7

    .line 36
    .line 37
    iget v6, v2, Lk8/e;->d:I

    .line 38
    .line 39
    sub-int/2addr v6, v4

    .line 40
    iput v6, v2, Lk8/e;->d:I

    .line 41
    .line 42
    iget-object v5, v5, Lc1/i2;->g:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v5, Lc1/i2;

    .line 45
    .line 46
    if-eqz v5, :cond_2

    .line 47
    .line 48
    iget-object v6, v5, Lc1/i2;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v6, Lk8/a;

    .line 51
    .line 52
    if-nez v6, :cond_1

    .line 53
    .line 54
    :cond_2
    move-object v5, v3

    .line 55
    goto :goto_0

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto :goto_4

    .line 58
    :cond_3
    invoke-virtual {v2}, Ljava/lang/Object;->notifyAll()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    .line 61
    monitor-exit v2

    .line 62
    iput-object v3, v1, Lc1/i2;->f:Ljava/lang/Object;

    .line 63
    .line 64
    iput-object v3, v1, Lc1/i2;->g:Ljava/lang/Object;

    .line 65
    .line 66
    :goto_1
    iget-object v1, v0, Lh8/v0;->d:Lc1/i2;

    .line 67
    .line 68
    iget v2, v0, Lh8/v0;->b:I

    .line 69
    .line 70
    iget-object v5, v1, Lc1/i2;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v5, Lk8/a;

    .line 73
    .line 74
    const/4 v6, 0x0

    .line 75
    if-nez v5, :cond_4

    .line 76
    .line 77
    move v5, v4

    .line 78
    goto :goto_2

    .line 79
    :cond_4
    move v5, v6

    .line 80
    :goto_2
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 81
    .line 82
    .line 83
    const-wide/16 v7, 0x0

    .line 84
    .line 85
    iput-wide v7, v1, Lc1/i2;->d:J

    .line 86
    .line 87
    int-to-long v9, v2

    .line 88
    iput-wide v9, v1, Lc1/i2;->e:J

    .line 89
    .line 90
    iget-object v1, v0, Lh8/v0;->d:Lc1/i2;

    .line 91
    .line 92
    iput-object v1, v0, Lh8/v0;->e:Lc1/i2;

    .line 93
    .line 94
    iput-object v1, v0, Lh8/v0;->f:Lc1/i2;

    .line 95
    .line 96
    iput-wide v7, v0, Lh8/v0;->g:J

    .line 97
    .line 98
    iget-object v0, v0, Lh8/v0;->a:Lk8/e;

    .line 99
    .line 100
    invoke-virtual {v0}, Lk8/e;->b()V

    .line 101
    .line 102
    .line 103
    iput v6, p0, Lh8/x0;->p:I

    .line 104
    .line 105
    iput v6, p0, Lh8/x0;->q:I

    .line 106
    .line 107
    iput v6, p0, Lh8/x0;->r:I

    .line 108
    .line 109
    iput v6, p0, Lh8/x0;->s:I

    .line 110
    .line 111
    iput-boolean v4, p0, Lh8/x0;->x:Z

    .line 112
    .line 113
    const-wide/high16 v0, -0x8000000000000000L

    .line 114
    .line 115
    iput-wide v0, p0, Lh8/x0;->t:J

    .line 116
    .line 117
    iput-wide v0, p0, Lh8/x0;->u:J

    .line 118
    .line 119
    iput-wide v0, p0, Lh8/x0;->v:J

    .line 120
    .line 121
    iput-boolean v6, p0, Lh8/x0;->w:Z

    .line 122
    .line 123
    iget-object v0, p0, Lh8/x0;->c:Lbb/g0;

    .line 124
    .line 125
    iget-object v1, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v1, Landroid/util/SparseArray;

    .line 128
    .line 129
    :goto_3
    invoke-virtual {v1}, Landroid/util/SparseArray;->size()I

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    if-ge v6, v2, :cond_5

    .line 134
    .line 135
    iget-object v2, v0, Lbb/g0;->g:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v2, Lf3/d;

    .line 138
    .line 139
    invoke-virtual {v1, v6}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v5

    .line 143
    invoke-virtual {v2, v5}, Lf3/d;->accept(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    add-int/lit8 v6, v6, 0x1

    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_5
    const/4 v2, -0x1

    .line 150
    iput v2, v0, Lbb/g0;->e:I

    .line 151
    .line 152
    invoke-virtual {v1}, Landroid/util/SparseArray;->clear()V

    .line 153
    .line 154
    .line 155
    if-eqz p1, :cond_6

    .line 156
    .line 157
    iput-object v3, p0, Lh8/x0;->z:Lt7/o;

    .line 158
    .line 159
    iput-boolean v4, p0, Lh8/x0;->y:Z

    .line 160
    .line 161
    iput-boolean v4, p0, Lh8/x0;->A:Z

    .line 162
    .line 163
    :cond_6
    return-void

    .line 164
    :goto_4
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 165
    throw p0
.end method

.method public final declared-synchronized m(JZ)Z
    .locals 11

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    monitor-enter p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 3
    const/4 v0, 0x0

    .line 4
    :try_start_1
    iput v0, p0, Lh8/x0;->s:I

    .line 5
    .line 6
    iget-object v1, p0, Lh8/x0;->a:Lh8/v0;

    .line 7
    .line 8
    iget-object v2, v1, Lh8/v0;->d:Lc1/i2;

    .line 9
    .line 10
    iput-object v2, v1, Lh8/v0;->e:Lc1/i2;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_5

    .line 11
    .line 12
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_4

    .line 13
    :try_start_3
    invoke-virtual {p0, v0}, Lh8/x0;->h(I)I

    .line 14
    .line 15
    .line 16
    move-result v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 17
    :try_start_4
    iget v1, p0, Lh8/x0;->s:I

    .line 18
    .line 19
    iget v2, p0, Lh8/x0;->p:I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 20
    .line 21
    const/4 v9, 0x1

    .line 22
    if-eq v1, v2, :cond_0

    .line 23
    .line 24
    move v3, v9

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v3, v0

    .line 27
    :goto_0
    if-eqz v3, :cond_1

    .line 28
    .line 29
    :try_start_5
    iget-object v3, p0, Lh8/x0;->n:[J

    .line 30
    .line 31
    aget-wide v3, v3, v6

    .line 32
    .line 33
    cmp-long v3, p1, v3

    .line 34
    .line 35
    if-ltz v3, :cond_1

    .line 36
    .line 37
    iget-wide v3, p0, Lh8/x0;->v:J

    .line 38
    .line 39
    cmp-long v3, p1, v3

    .line 40
    .line 41
    if-lez v3, :cond_2

    .line 42
    .line 43
    if-nez p3, :cond_2

    .line 44
    .line 45
    :cond_1
    move-object v3, p0

    .line 46
    goto :goto_5

    .line 47
    :cond_2
    iget-boolean v3, p0, Lh8/x0;->A:Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 48
    .line 49
    const/4 v10, -0x1

    .line 50
    if-eqz v3, :cond_7

    .line 51
    .line 52
    sub-int/2addr v2, v1

    .line 53
    move v1, v0

    .line 54
    :goto_1
    if-ge v1, v2, :cond_5

    .line 55
    .line 56
    :try_start_6
    iget-object v3, p0, Lh8/x0;->n:[J

    .line 57
    .line 58
    aget-wide v3, v3, v6

    .line 59
    .line 60
    cmp-long v3, v3, p1

    .line 61
    .line 62
    if-ltz v3, :cond_3

    .line 63
    .line 64
    move v2, v1

    .line 65
    goto :goto_2

    .line 66
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 67
    .line 68
    iget v3, p0, Lh8/x0;->i:I
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 69
    .line 70
    if-ne v6, v3, :cond_4

    .line 71
    .line 72
    move v6, v0

    .line 73
    :cond_4
    add-int/lit8 v1, v1, 0x1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :catchall_0
    move-exception v0

    .line 77
    move-object p1, v0

    .line 78
    move-object v3, p0

    .line 79
    goto :goto_8

    .line 80
    :cond_5
    if-eqz p3, :cond_6

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_6
    move v2, v10

    .line 84
    :goto_2
    move-object v3, p0

    .line 85
    move-wide v4, p1

    .line 86
    goto :goto_3

    .line 87
    :cond_7
    sub-int v7, v2, v1

    .line 88
    .line 89
    const/4 v8, 0x1

    .line 90
    move-object v3, p0

    .line 91
    move-wide v4, p1

    .line 92
    :try_start_7
    invoke-virtual/range {v3 .. v8}, Lh8/x0;->g(JIIZ)I

    .line 93
    .line 94
    .line 95
    move-result v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 96
    :goto_3
    if-ne v2, v10, :cond_8

    .line 97
    .line 98
    monitor-exit v3

    .line 99
    return v0

    .line 100
    :cond_8
    :try_start_8
    iput-wide v4, v3, Lh8/x0;->t:J

    .line 101
    .line 102
    iget p0, v3, Lh8/x0;->s:I

    .line 103
    .line 104
    add-int/2addr p0, v2

    .line 105
    iput p0, v3, Lh8/x0;->s:I
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 106
    .line 107
    monitor-exit v3

    .line 108
    return v9

    .line 109
    :catchall_1
    move-exception v0

    .line 110
    :goto_4
    move-object p1, v0

    .line 111
    goto :goto_8

    .line 112
    :catchall_2
    move-exception v0

    .line 113
    move-object v3, p0

    .line 114
    goto :goto_4

    .line 115
    :goto_5
    monitor-exit v3

    .line 116
    return v0

    .line 117
    :catchall_3
    move-exception v0

    .line 118
    move-object v3, p0

    .line 119
    :goto_6
    move-object p0, v0

    .line 120
    move-object p1, p0

    .line 121
    goto :goto_8

    .line 122
    :catchall_4
    move-exception v0

    .line 123
    move-object v3, p0

    .line 124
    goto :goto_6

    .line 125
    :catchall_5
    move-exception v0

    .line 126
    move-object v3, p0

    .line 127
    :goto_7
    move-object p0, v0

    .line 128
    :try_start_9
    monitor-exit v3
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_7

    .line 129
    :try_start_a
    throw p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_6

    .line 130
    :catchall_6
    move-exception v0

    .line 131
    goto :goto_6

    .line 132
    :catchall_7
    move-exception v0

    .line 133
    goto :goto_7

    .line 134
    :goto_8
    :try_start_b
    monitor-exit v3
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 135
    throw p1
.end method

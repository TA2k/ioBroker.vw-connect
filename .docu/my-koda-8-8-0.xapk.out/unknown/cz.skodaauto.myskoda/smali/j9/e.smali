.class public final Lj9/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public a:Lo8/q;

.field public b:Lj9/j;

.field public c:Z


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 0

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Lj9/e;->e(Lo8/p;)Z

    .line 2
    .line 3
    .line 4
    move-result p0
    :try_end_0
    .catch Lt7/e0; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return p0

    .line 6
    :catch_0
    const/4 p0, 0x0

    .line 7
    return p0
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lj9/e;->a:Lo8/q;

    .line 2
    .line 3
    return-void
.end method

.method public final d(JJ)V
    .locals 5

    .line 1
    iget-object p0, p0, Lj9/e;->b:Lj9/j;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lj9/j;->a:Lj9/f;

    .line 6
    .line 7
    iget-object v1, v0, Lj9/f;->a:Lj9/g;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    iput v2, v1, Lj9/g;->a:I

    .line 11
    .line 12
    const-wide/16 v3, 0x0

    .line 13
    .line 14
    iput-wide v3, v1, Lj9/g;->b:J

    .line 15
    .line 16
    iput v2, v1, Lj9/g;->c:I

    .line 17
    .line 18
    iput v2, v1, Lj9/g;->d:I

    .line 19
    .line 20
    iput v2, v1, Lj9/g;->e:I

    .line 21
    .line 22
    iget-object v1, v0, Lj9/f;->b:Lw7/p;

    .line 23
    .line 24
    invoke-virtual {v1, v2}, Lw7/p;->F(I)V

    .line 25
    .line 26
    .line 27
    const/4 v1, -0x1

    .line 28
    iput v1, v0, Lj9/f;->c:I

    .line 29
    .line 30
    iput-boolean v2, v0, Lj9/f;->e:Z

    .line 31
    .line 32
    cmp-long p1, p1, v3

    .line 33
    .line 34
    if-nez p1, :cond_0

    .line 35
    .line 36
    iget-boolean p1, p0, Lj9/j;->l:Z

    .line 37
    .line 38
    xor-int/lit8 p1, p1, 0x1

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lj9/j;->d(Z)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_0
    iget p1, p0, Lj9/j;->h:I

    .line 45
    .line 46
    if-eqz p1, :cond_1

    .line 47
    .line 48
    iget p1, p0, Lj9/j;->i:I

    .line 49
    .line 50
    int-to-long p1, p1

    .line 51
    mul-long/2addr p1, p3

    .line 52
    const-wide/32 p3, 0xf4240

    .line 53
    .line 54
    .line 55
    div-long/2addr p1, p3

    .line 56
    iput-wide p1, p0, Lj9/j;->e:J

    .line 57
    .line 58
    iget-object p3, p0, Lj9/j;->d:Lj9/h;

    .line 59
    .line 60
    sget-object p4, Lw7/w;->a:Ljava/lang/String;

    .line 61
    .line 62
    invoke-interface {p3, p1, p2}, Lj9/h;->q(J)V

    .line 63
    .line 64
    .line 65
    const/4 p1, 0x2

    .line 66
    iput p1, p0, Lj9/j;->h:I

    .line 67
    .line 68
    :cond_1
    return-void
.end method

.method public final e(Lo8/p;)Z
    .locals 8

    .line 1
    new-instance v0, Lj9/g;

    .line 2
    .line 3
    invoke-direct {v0}, Lj9/g;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-virtual {v0, p1, v1}, Lj9/g;->a(Lo8/p;Z)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, 0x0

    .line 12
    if-eqz v2, :cond_3

    .line 13
    .line 14
    iget v2, v0, Lj9/g;->a:I

    .line 15
    .line 16
    const/4 v4, 0x2

    .line 17
    and-int/2addr v2, v4

    .line 18
    if-eq v2, v4, :cond_0

    .line 19
    .line 20
    goto :goto_2

    .line 21
    :cond_0
    iget v0, v0, Lj9/g;->e:I

    .line 22
    .line 23
    const/16 v2, 0x8

    .line 24
    .line 25
    invoke-static {v0, v2}, Ljava/lang/Math;->min(II)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    new-instance v2, Lw7/p;

    .line 30
    .line 31
    invoke-direct {v2, v0}, Lw7/p;-><init>(I)V

    .line 32
    .line 33
    .line 34
    iget-object v4, v2, Lw7/p;->a:[B

    .line 35
    .line 36
    invoke-interface {p1, v4, v3, v0}, Lo8/p;->o([BII)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    const/4 v0, 0x5

    .line 47
    if-lt p1, v0, :cond_1

    .line 48
    .line 49
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    const/16 v0, 0x7f

    .line 54
    .line 55
    if-ne p1, v0, :cond_1

    .line 56
    .line 57
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 58
    .line 59
    .line 60
    move-result-wide v4

    .line 61
    const-wide/32 v6, 0x464c4143

    .line 62
    .line 63
    .line 64
    cmp-long p1, v4, v6

    .line 65
    .line 66
    if-nez p1, :cond_1

    .line 67
    .line 68
    new-instance p1, Lj9/c;

    .line 69
    .line 70
    invoke-direct {p1}, Lj9/j;-><init>()V

    .line 71
    .line 72
    .line 73
    iput-object p1, p0, Lj9/e;->b:Lj9/j;

    .line 74
    .line 75
    return v1

    .line 76
    :cond_1
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 77
    .line 78
    .line 79
    :try_start_0
    invoke-static {v1, v2, v1}, Lo8/b;->x(ILw7/p;Z)Z

    .line 80
    .line 81
    .line 82
    move-result p1
    :try_end_0
    .catch Lt7/e0; {:try_start_0 .. :try_end_0} :catch_0

    .line 83
    goto :goto_0

    .line 84
    :catch_0
    move p1, v3

    .line 85
    :goto_0
    if-eqz p1, :cond_2

    .line 86
    .line 87
    new-instance p1, Lj9/k;

    .line 88
    .line 89
    invoke-direct {p1}, Lj9/j;-><init>()V

    .line 90
    .line 91
    .line 92
    iput-object p1, p0, Lj9/e;->b:Lj9/j;

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_2
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 96
    .line 97
    .line 98
    sget-object p1, Lj9/i;->o:[B

    .line 99
    .line 100
    invoke-static {v2, p1}, Lj9/i;->e(Lw7/p;[B)Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-eqz p1, :cond_3

    .line 105
    .line 106
    new-instance p1, Lj9/i;

    .line 107
    .line 108
    invoke-direct {p1}, Lj9/j;-><init>()V

    .line 109
    .line 110
    .line 111
    iput-object p1, p0, Lj9/e;->b:Lj9/j;

    .line 112
    .line 113
    :goto_1
    return v1

    .line 114
    :cond_3
    :goto_2
    return v3
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lj9/e;->a:Lo8/q;

    .line 6
    .line 7
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object v2, v0, Lj9/e;->b:Lj9/j;

    .line 11
    .line 12
    if-nez v2, :cond_1

    .line 13
    .line 14
    invoke-virtual/range {p0 .. p1}, Lj9/e;->e(Lo8/p;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-interface {v1}, Lo8/p;->e()V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const-string v0, "Failed to determine bitstream type"

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    throw v0

    .line 32
    :cond_1
    :goto_0
    iget-boolean v2, v0, Lj9/e;->c:Z

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    const/4 v4, 0x1

    .line 36
    if-nez v2, :cond_2

    .line 37
    .line 38
    iget-object v2, v0, Lj9/e;->a:Lo8/q;

    .line 39
    .line 40
    invoke-interface {v2, v3, v4}, Lo8/q;->q(II)Lo8/i0;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    iget-object v5, v0, Lj9/e;->a:Lo8/q;

    .line 45
    .line 46
    invoke-interface {v5}, Lo8/q;->m()V

    .line 47
    .line 48
    .line 49
    iget-object v5, v0, Lj9/e;->b:Lj9/j;

    .line 50
    .line 51
    iget-object v6, v0, Lj9/e;->a:Lo8/q;

    .line 52
    .line 53
    iput-object v6, v5, Lj9/j;->c:Lo8/q;

    .line 54
    .line 55
    iput-object v2, v5, Lj9/j;->b:Lo8/i0;

    .line 56
    .line 57
    invoke-virtual {v5, v4}, Lj9/j;->d(Z)V

    .line 58
    .line 59
    .line 60
    iput-boolean v4, v0, Lj9/e;->c:Z

    .line 61
    .line 62
    :cond_2
    iget-object v8, v0, Lj9/e;->b:Lj9/j;

    .line 63
    .line 64
    iget-object v0, v8, Lj9/j;->a:Lj9/f;

    .line 65
    .line 66
    iget-object v2, v8, Lj9/j;->b:Lo8/i0;

    .line 67
    .line 68
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 72
    .line 73
    iget v2, v8, Lj9/j;->h:I

    .line 74
    .line 75
    const-wide/16 v5, -0x1

    .line 76
    .line 77
    const/4 v7, -0x1

    .line 78
    const/4 v9, 0x3

    .line 79
    const/4 v10, 0x2

    .line 80
    if-eqz v2, :cond_c

    .line 81
    .line 82
    if-eq v2, v4, :cond_b

    .line 83
    .line 84
    if-eq v2, v10, :cond_4

    .line 85
    .line 86
    if-ne v2, v9, :cond_3

    .line 87
    .line 88
    return v7

    .line 89
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 92
    .line 93
    .line 94
    throw v0

    .line 95
    :cond_4
    iget-object v2, v8, Lj9/j;->d:Lj9/h;

    .line 96
    .line 97
    invoke-interface {v2, v1}, Lj9/h;->k(Lo8/p;)J

    .line 98
    .line 99
    .line 100
    move-result-wide v10

    .line 101
    const-wide/16 v12, 0x0

    .line 102
    .line 103
    cmp-long v2, v10, v12

    .line 104
    .line 105
    if-ltz v2, :cond_5

    .line 106
    .line 107
    move-object/from16 v2, p2

    .line 108
    .line 109
    iput-wide v10, v2, Lo8/s;->a:J

    .line 110
    .line 111
    return v4

    .line 112
    :cond_5
    cmp-long v2, v10, v5

    .line 113
    .line 114
    if-gez v2, :cond_6

    .line 115
    .line 116
    const-wide/16 v14, 0x2

    .line 117
    .line 118
    add-long/2addr v10, v14

    .line 119
    neg-long v10, v10

    .line 120
    invoke-virtual {v8, v10, v11}, Lj9/j;->a(J)V

    .line 121
    .line 122
    .line 123
    :cond_6
    iget-boolean v2, v8, Lj9/j;->l:Z

    .line 124
    .line 125
    if-nez v2, :cond_7

    .line 126
    .line 127
    iget-object v2, v8, Lj9/j;->d:Lj9/h;

    .line 128
    .line 129
    invoke-interface {v2}, Lj9/h;->m()Lo8/c0;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iget-object v10, v8, Lj9/j;->c:Lo8/q;

    .line 137
    .line 138
    invoke-interface {v10, v2}, Lo8/q;->c(Lo8/c0;)V

    .line 139
    .line 140
    .line 141
    iget-object v10, v8, Lj9/j;->b:Lo8/i0;

    .line 142
    .line 143
    invoke-interface {v2}, Lo8/c0;->l()J

    .line 144
    .line 145
    .line 146
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    iput-boolean v4, v8, Lj9/j;->l:Z

    .line 150
    .line 151
    :cond_7
    iget-wide v10, v8, Lj9/j;->k:J

    .line 152
    .line 153
    cmp-long v2, v10, v12

    .line 154
    .line 155
    if-gtz v2, :cond_9

    .line 156
    .line 157
    invoke-virtual {v0, v1}, Lj9/f;->b(Lo8/p;)Z

    .line 158
    .line 159
    .line 160
    move-result v1

    .line 161
    if-eqz v1, :cond_8

    .line 162
    .line 163
    goto :goto_1

    .line 164
    :cond_8
    iput v9, v8, Lj9/j;->h:I

    .line 165
    .line 166
    return v7

    .line 167
    :cond_9
    :goto_1
    iput-wide v12, v8, Lj9/j;->k:J

    .line 168
    .line 169
    iget-object v0, v0, Lj9/f;->b:Lw7/p;

    .line 170
    .line 171
    invoke-virtual {v8, v0}, Lj9/j;->b(Lw7/p;)J

    .line 172
    .line 173
    .line 174
    move-result-wide v1

    .line 175
    cmp-long v4, v1, v12

    .line 176
    .line 177
    if-ltz v4, :cond_a

    .line 178
    .line 179
    iget-wide v9, v8, Lj9/j;->g:J

    .line 180
    .line 181
    add-long v11, v9, v1

    .line 182
    .line 183
    iget-wide v13, v8, Lj9/j;->e:J

    .line 184
    .line 185
    cmp-long v4, v11, v13

    .line 186
    .line 187
    if-ltz v4, :cond_a

    .line 188
    .line 189
    const-wide/32 v11, 0xf4240

    .line 190
    .line 191
    .line 192
    mul-long/2addr v9, v11

    .line 193
    iget v4, v8, Lj9/j;->i:I

    .line 194
    .line 195
    int-to-long v11, v4

    .line 196
    div-long v14, v9, v11

    .line 197
    .line 198
    iget-object v4, v8, Lj9/j;->b:Lo8/i0;

    .line 199
    .line 200
    iget v7, v0, Lw7/p;->c:I

    .line 201
    .line 202
    invoke-interface {v4, v0, v7, v3}, Lo8/i0;->a(Lw7/p;II)V

    .line 203
    .line 204
    .line 205
    iget-object v13, v8, Lj9/j;->b:Lo8/i0;

    .line 206
    .line 207
    iget v0, v0, Lw7/p;->c:I

    .line 208
    .line 209
    const/16 v18, 0x0

    .line 210
    .line 211
    const/16 v19, 0x0

    .line 212
    .line 213
    const/16 v16, 0x1

    .line 214
    .line 215
    move/from16 v17, v0

    .line 216
    .line 217
    invoke-interface/range {v13 .. v19}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 218
    .line 219
    .line 220
    iput-wide v5, v8, Lj9/j;->e:J

    .line 221
    .line 222
    :cond_a
    iget-wide v4, v8, Lj9/j;->g:J

    .line 223
    .line 224
    add-long/2addr v4, v1

    .line 225
    iput-wide v4, v8, Lj9/j;->g:J

    .line 226
    .line 227
    return v3

    .line 228
    :cond_b
    iget-wide v4, v8, Lj9/j;->f:J

    .line 229
    .line 230
    long-to-int v0, v4

    .line 231
    invoke-interface {v1, v0}, Lo8/p;->n(I)V

    .line 232
    .line 233
    .line 234
    iput v10, v8, Lj9/j;->h:I

    .line 235
    .line 236
    return v3

    .line 237
    :cond_c
    :goto_2
    invoke-virtual {v0, v1}, Lj9/f;->b(Lo8/p;)Z

    .line 238
    .line 239
    .line 240
    move-result v2

    .line 241
    iget-object v11, v0, Lj9/f;->b:Lw7/p;

    .line 242
    .line 243
    if-nez v2, :cond_d

    .line 244
    .line 245
    iput v9, v8, Lj9/j;->h:I

    .line 246
    .line 247
    return v7

    .line 248
    :cond_d
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 249
    .line 250
    .line 251
    move-result-wide v12

    .line 252
    iget-wide v14, v8, Lj9/j;->f:J

    .line 253
    .line 254
    sub-long/2addr v12, v14

    .line 255
    iput-wide v12, v8, Lj9/j;->k:J

    .line 256
    .line 257
    iget-object v2, v8, Lj9/j;->j:Lb81/c;

    .line 258
    .line 259
    invoke-virtual {v8, v11, v14, v15, v2}, Lj9/j;->c(Lw7/p;JLb81/c;)Z

    .line 260
    .line 261
    .line 262
    move-result v2

    .line 263
    if-eqz v2, :cond_e

    .line 264
    .line 265
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 266
    .line 267
    .line 268
    move-result-wide v11

    .line 269
    iput-wide v11, v8, Lj9/j;->f:J

    .line 270
    .line 271
    goto :goto_2

    .line 272
    :cond_e
    iget-object v2, v8, Lj9/j;->j:Lb81/c;

    .line 273
    .line 274
    iget-object v2, v2, Lb81/c;->e:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v2, Lt7/o;

    .line 277
    .line 278
    iget v7, v2, Lt7/o;->G:I

    .line 279
    .line 280
    iput v7, v8, Lj9/j;->i:I

    .line 281
    .line 282
    iget-boolean v7, v8, Lj9/j;->m:Z

    .line 283
    .line 284
    if-nez v7, :cond_f

    .line 285
    .line 286
    iget-object v7, v8, Lj9/j;->b:Lo8/i0;

    .line 287
    .line 288
    invoke-interface {v7, v2}, Lo8/i0;->c(Lt7/o;)V

    .line 289
    .line 290
    .line 291
    iput-boolean v4, v8, Lj9/j;->m:Z

    .line 292
    .line 293
    :cond_f
    iget-object v2, v8, Lj9/j;->j:Lb81/c;

    .line 294
    .line 295
    iget-object v2, v2, Lb81/c;->f:Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v2, Lc1/i2;

    .line 298
    .line 299
    if-eqz v2, :cond_10

    .line 300
    .line 301
    iput-object v2, v8, Lj9/j;->d:Lj9/h;

    .line 302
    .line 303
    :goto_3
    move v2, v10

    .line 304
    move-object v0, v11

    .line 305
    goto :goto_5

    .line 306
    :cond_10
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 307
    .line 308
    .line 309
    move-result-wide v12

    .line 310
    cmp-long v2, v12, v5

    .line 311
    .line 312
    if-nez v2, :cond_11

    .line 313
    .line 314
    new-instance v0, Lwe0/b;

    .line 315
    .line 316
    const/4 v1, 0x7

    .line 317
    invoke-direct {v0, v1}, Lwe0/b;-><init>(I)V

    .line 318
    .line 319
    .line 320
    iput-object v0, v8, Lj9/j;->d:Lj9/h;

    .line 321
    .line 322
    goto :goto_3

    .line 323
    :cond_11
    iget-object v0, v0, Lj9/f;->a:Lj9/g;

    .line 324
    .line 325
    iget v2, v0, Lj9/g;->a:I

    .line 326
    .line 327
    and-int/lit8 v2, v2, 0x4

    .line 328
    .line 329
    if-eqz v2, :cond_12

    .line 330
    .line 331
    move/from16 v17, v4

    .line 332
    .line 333
    goto :goto_4

    .line 334
    :cond_12
    move/from16 v17, v3

    .line 335
    .line 336
    :goto_4
    new-instance v7, Lj9/b;

    .line 337
    .line 338
    move v2, v10

    .line 339
    iget-wide v9, v8, Lj9/j;->f:J

    .line 340
    .line 341
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 342
    .line 343
    .line 344
    move-result-wide v4

    .line 345
    iget v1, v0, Lj9/g;->d:I

    .line 346
    .line 347
    iget v6, v0, Lj9/g;->e:I

    .line 348
    .line 349
    add-int/2addr v1, v6

    .line 350
    int-to-long v13, v1

    .line 351
    iget-wide v0, v0, Lj9/g;->b:J

    .line 352
    .line 353
    move-wide v15, v0

    .line 354
    move-object v0, v11

    .line 355
    move-wide v11, v4

    .line 356
    invoke-direct/range {v7 .. v17}, Lj9/b;-><init>(Lj9/j;JJJJZ)V

    .line 357
    .line 358
    .line 359
    iput-object v7, v8, Lj9/j;->d:Lj9/h;

    .line 360
    .line 361
    :goto_5
    iput v2, v8, Lj9/j;->h:I

    .line 362
    .line 363
    iget-object v1, v0, Lw7/p;->a:[B

    .line 364
    .line 365
    array-length v2, v1

    .line 366
    const v4, 0xfe01

    .line 367
    .line 368
    .line 369
    if-ne v2, v4, :cond_13

    .line 370
    .line 371
    return v3

    .line 372
    :cond_13
    iget v2, v0, Lw7/p;->c:I

    .line 373
    .line 374
    invoke-static {v4, v2}, Ljava/lang/Math;->max(II)I

    .line 375
    .line 376
    .line 377
    move-result v2

    .line 378
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    iget v2, v0, Lw7/p;->c:I

    .line 383
    .line 384
    invoke-virtual {v0, v2, v1}, Lw7/p;->G(I[B)V

    .line 385
    .line 386
    .line 387
    return v3
.end method

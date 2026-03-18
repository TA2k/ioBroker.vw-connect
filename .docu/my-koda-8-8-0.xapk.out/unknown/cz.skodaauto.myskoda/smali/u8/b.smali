.class public final Lu8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:Lw7/p;

.field public final b:Lw7/p;

.field public final c:Lw7/p;

.field public final d:Lw7/p;

.field public final e:Lu8/c;

.field public f:Lo8/q;

.field public g:I

.field public h:Z

.field public i:J

.field public j:I

.field public k:I

.field public l:I

.field public m:J

.field public n:Z

.field public o:Lu8/a;

.field public p:Lu8/d;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lw7/p;

    .line 5
    .line 6
    const/4 v1, 0x4

    .line 7
    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lu8/b;->a:Lw7/p;

    .line 11
    .line 12
    new-instance v0, Lw7/p;

    .line 13
    .line 14
    const/16 v1, 0x9

    .line 15
    .line 16
    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lu8/b;->b:Lw7/p;

    .line 20
    .line 21
    new-instance v0, Lw7/p;

    .line 22
    .line 23
    const/16 v1, 0xb

    .line 24
    .line 25
    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lu8/b;->c:Lw7/p;

    .line 29
    .line 30
    new-instance v0, Lw7/p;

    .line 31
    .line 32
    invoke-direct {v0}, Lw7/p;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lu8/b;->d:Lw7/p;

    .line 36
    .line 37
    new-instance v0, Lu8/c;

    .line 38
    .line 39
    new-instance v1, Lo8/n;

    .line 40
    .line 41
    invoke-direct {v1}, Lo8/n;-><init>()V

    .line 42
    .line 43
    .line 44
    const/16 v2, 0x8

    .line 45
    .line 46
    invoke-direct {v0, v1, v2}, Lap0/o;-><init>(Ljava/lang/Object;I)V

    .line 47
    .line 48
    .line 49
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    iput-wide v1, v0, Lu8/c;->f:J

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    new-array v2, v1, [J

    .line 58
    .line 59
    iput-object v2, v0, Lu8/c;->g:[J

    .line 60
    .line 61
    new-array v1, v1, [J

    .line 62
    .line 63
    iput-object v1, v0, Lu8/c;->h:[J

    .line 64
    .line 65
    iput-object v0, p0, Lu8/b;->e:Lu8/c;

    .line 66
    .line 67
    const/4 v0, 0x1

    .line 68
    iput v0, p0, Lu8/b;->g:I

    .line 69
    .line 70
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 3

    .line 1
    iget-object p0, p0, Lu8/b;->a:Lw7/p;

    .line 2
    .line 3
    iget-object v0, p0, Lw7/p;->a:[B

    .line 4
    .line 5
    check-cast p1, Lo8/l;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x3

    .line 9
    invoke-virtual {p1, v0, v1, v2, v1}, Lo8/l;->b([BIIZ)Z

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v1}, Lw7/p;->I(I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lw7/p;->z()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const v2, 0x464c56

    .line 20
    .line 21
    .line 22
    if-eq v0, v2, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object v0, p0, Lw7/p;->a:[B

    .line 26
    .line 27
    const/4 v2, 0x2

    .line 28
    invoke-virtual {p1, v0, v1, v2, v1}, Lo8/l;->b([BIIZ)Z

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, v1}, Lw7/p;->I(I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lw7/p;->C()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    and-int/lit16 v0, v0, 0xfa

    .line 39
    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-virtual {p1, v0, v1, v2, v1}, Lo8/l;->b([BIIZ)Z

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, v1}, Lw7/p;->I(I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iput v1, p1, Lo8/l;->i:I

    .line 57
    .line 58
    invoke-virtual {p1, v0, v1}, Lo8/l;->c(IZ)Z

    .line 59
    .line 60
    .line 61
    iget-object v0, p0, Lw7/p;->a:[B

    .line 62
    .line 63
    invoke-virtual {p1, v0, v1, v2, v1}, Lo8/l;->b([BIIZ)Z

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, v1}, Lw7/p;->I(I)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    if-nez p0, :cond_2

    .line 74
    .line 75
    const/4 p0, 0x1

    .line 76
    return p0

    .line 77
    :cond_2
    :goto_0
    return v1
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lu8/b;->f:Lo8/q;

    .line 2
    .line 3
    return-void
.end method

.method public final d(JJ)V
    .locals 0

    .line 1
    const-wide/16 p3, 0x0

    .line 2
    .line 3
    cmp-long p1, p1, p3

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    const/4 p1, 0x1

    .line 9
    iput p1, p0, Lu8/b;->g:I

    .line 10
    .line 11
    iput-boolean p2, p0, Lu8/b;->h:Z

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p1, 0x3

    .line 15
    iput p1, p0, Lu8/b;->g:I

    .line 16
    .line 17
    :goto_0
    iput p2, p0, Lu8/b;->j:I

    .line 18
    .line 19
    return-void
.end method

.method public final e(Lo8/p;)Lw7/p;
    .locals 5

    .line 1
    iget v0, p0, Lu8/b;->l:I

    .line 2
    .line 3
    iget-object v1, p0, Lu8/b;->d:Lw7/p;

    .line 4
    .line 5
    iget-object v2, v1, Lw7/p;->a:[B

    .line 6
    .line 7
    array-length v3, v2

    .line 8
    const/4 v4, 0x0

    .line 9
    if-le v0, v3, :cond_0

    .line 10
    .line 11
    array-length v2, v2

    .line 12
    mul-int/lit8 v2, v2, 0x2

    .line 13
    .line 14
    invoke-static {v2, v0}, Ljava/lang/Math;->max(II)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    new-array v0, v0, [B

    .line 19
    .line 20
    invoke-virtual {v1, v4, v0}, Lw7/p;->G(I[B)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v1, v4}, Lw7/p;->I(I)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget v0, p0, Lu8/b;->l:I

    .line 28
    .line 29
    invoke-virtual {v1, v0}, Lw7/p;->H(I)V

    .line 30
    .line 31
    .line 32
    iget-object v0, v1, Lw7/p;->a:[B

    .line 33
    .line 34
    iget p0, p0, Lu8/b;->l:I

    .line 35
    .line 36
    invoke-interface {p1, v0, v4, p0}, Lo8/p;->readFully([BII)V

    .line 37
    .line 38
    .line 39
    return-object v1
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lu8/b;->f:Lo8/q;

    .line 6
    .line 7
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    :goto_0
    iget v2, v0, Lu8/b;->g:I

    .line 11
    .line 12
    const/16 v3, 0x9

    .line 13
    .line 14
    const/16 v4, 0x8

    .line 15
    .line 16
    const/4 v5, 0x2

    .line 17
    const/4 v6, 0x4

    .line 18
    const/4 v7, 0x1

    .line 19
    if-eq v2, v7, :cond_29

    .line 20
    .line 21
    const/4 v9, 0x3

    .line 22
    if-eq v2, v5, :cond_28

    .line 23
    .line 24
    if-eq v2, v9, :cond_26

    .line 25
    .line 26
    if-ne v2, v6, :cond_25

    .line 27
    .line 28
    iget-boolean v2, v0, Lu8/b;->h:Z

    .line 29
    .line 30
    const-wide v9, -0x7fffffffffffffffL    # -4.9E-324

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    iget-object v13, v0, Lu8/b;->e:Lu8/c;

    .line 36
    .line 37
    if-eqz v2, :cond_1

    .line 38
    .line 39
    iget-wide v14, v0, Lu8/b;->i:J

    .line 40
    .line 41
    iget-wide v11, v0, Lu8/b;->m:J

    .line 42
    .line 43
    add-long/2addr v14, v11

    .line 44
    :goto_1
    move-wide/from16 v17, v14

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_1
    iget-wide v11, v13, Lu8/c;->f:J

    .line 48
    .line 49
    cmp-long v2, v11, v9

    .line 50
    .line 51
    if-nez v2, :cond_2

    .line 52
    .line 53
    const-wide/16 v17, 0x0

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    iget-wide v14, v0, Lu8/b;->m:J

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :goto_2
    iget v2, v0, Lu8/b;->k:I

    .line 60
    .line 61
    if-ne v2, v4, :cond_e

    .line 62
    .line 63
    iget-object v4, v0, Lu8/b;->o:Lu8/a;

    .line 64
    .line 65
    if-eqz v4, :cond_e

    .line 66
    .line 67
    iget-boolean v2, v0, Lu8/b;->n:Z

    .line 68
    .line 69
    if-nez v2, :cond_3

    .line 70
    .line 71
    iget-object v2, v0, Lu8/b;->f:Lo8/q;

    .line 72
    .line 73
    new-instance v3, Lo8/t;

    .line 74
    .line 75
    invoke-direct {v3, v9, v10}, Lo8/t;-><init>(J)V

    .line 76
    .line 77
    .line 78
    invoke-interface {v2, v3}, Lo8/q;->c(Lo8/c0;)V

    .line 79
    .line 80
    .line 81
    iput-boolean v7, v0, Lu8/b;->n:Z

    .line 82
    .line 83
    :cond_3
    iget-object v2, v0, Lu8/b;->o:Lu8/a;

    .line 84
    .line 85
    invoke-virtual/range {p0 .. p1}, Lu8/b;->e(Lo8/p;)Lw7/p;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    iget-object v4, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v4, Lo8/i0;

    .line 92
    .line 93
    iget-boolean v11, v2, Lu8/a;->f:Z

    .line 94
    .line 95
    const/4 v12, 0x1

    .line 96
    if-nez v11, :cond_9

    .line 97
    .line 98
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 99
    .line 100
    .line 101
    move-result v11

    .line 102
    shr-int/lit8 v14, v11, 0x4

    .line 103
    .line 104
    and-int/lit8 v14, v14, 0xf

    .line 105
    .line 106
    iput v14, v2, Lu8/a;->h:I

    .line 107
    .line 108
    const-string v15, "video/x-flv"

    .line 109
    .line 110
    const/16 p2, 0x0

    .line 111
    .line 112
    const/4 v8, 0x2

    .line 113
    if-ne v14, v8, :cond_4

    .line 114
    .line 115
    shr-int/lit8 v8, v11, 0x2

    .line 116
    .line 117
    and-int/lit8 v8, v8, 0x3

    .line 118
    .line 119
    sget-object v11, Lu8/a;->i:[I

    .line 120
    .line 121
    aget v8, v11, v8

    .line 122
    .line 123
    new-instance v11, Lt7/n;

    .line 124
    .line 125
    invoke-direct {v11}, Lt7/n;-><init>()V

    .line 126
    .line 127
    .line 128
    invoke-static {v15}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v14

    .line 132
    iput-object v14, v11, Lt7/n;->l:Ljava/lang/String;

    .line 133
    .line 134
    const-string v14, "audio/mpeg"

    .line 135
    .line 136
    invoke-static {v14}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v14

    .line 140
    iput-object v14, v11, Lt7/n;->m:Ljava/lang/String;

    .line 141
    .line 142
    iput v12, v11, Lt7/n;->E:I

    .line 143
    .line 144
    iput v8, v11, Lt7/n;->F:I

    .line 145
    .line 146
    invoke-static {v11, v4}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 147
    .line 148
    .line 149
    iput-boolean v12, v2, Lu8/a;->g:Z

    .line 150
    .line 151
    goto :goto_5

    .line 152
    :cond_4
    const/4 v8, 0x7

    .line 153
    if-eq v14, v8, :cond_7

    .line 154
    .line 155
    const/16 v11, 0x8

    .line 156
    .line 157
    if-ne v14, v11, :cond_5

    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_5
    const/16 v4, 0xa

    .line 161
    .line 162
    if-ne v14, v4, :cond_6

    .line 163
    .line 164
    goto :goto_5

    .line 165
    :cond_6
    new-instance v0, Lh8/f1;

    .line 166
    .line 167
    new-instance v1, Ljava/lang/StringBuilder;

    .line 168
    .line 169
    const-string v3, "Audio format not supported: "

    .line 170
    .line 171
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    iget v2, v2, Lu8/a;->h:I

    .line 175
    .line 176
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    invoke-direct {v0, v1}, Lh8/f1;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw v0

    .line 187
    :cond_7
    :goto_3
    if-ne v14, v8, :cond_8

    .line 188
    .line 189
    const-string v8, "audio/g711-alaw"

    .line 190
    .line 191
    goto :goto_4

    .line 192
    :cond_8
    const-string v8, "audio/g711-mlaw"

    .line 193
    .line 194
    :goto_4
    new-instance v11, Lt7/n;

    .line 195
    .line 196
    invoke-direct {v11}, Lt7/n;-><init>()V

    .line 197
    .line 198
    .line 199
    invoke-static {v15}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v14

    .line 203
    iput-object v14, v11, Lt7/n;->l:Ljava/lang/String;

    .line 204
    .line 205
    invoke-static {v8}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v8

    .line 209
    iput-object v8, v11, Lt7/n;->m:Ljava/lang/String;

    .line 210
    .line 211
    iput v12, v11, Lt7/n;->E:I

    .line 212
    .line 213
    const/16 v8, 0x1f40

    .line 214
    .line 215
    iput v8, v11, Lt7/n;->F:I

    .line 216
    .line 217
    invoke-static {v11, v4}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 218
    .line 219
    .line 220
    iput-boolean v12, v2, Lu8/a;->g:Z

    .line 221
    .line 222
    :goto_5
    iput-boolean v12, v2, Lu8/a;->f:Z

    .line 223
    .line 224
    goto :goto_6

    .line 225
    :cond_9
    const/16 p2, 0x0

    .line 226
    .line 227
    invoke-virtual {v3, v12}, Lw7/p;->J(I)V

    .line 228
    .line 229
    .line 230
    :goto_6
    iget-object v4, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v4, Lo8/i0;

    .line 233
    .line 234
    iget v8, v2, Lu8/a;->h:I

    .line 235
    .line 236
    const/4 v11, 0x2

    .line 237
    const/4 v12, 0x1

    .line 238
    const/4 v14, 0x0

    .line 239
    if-ne v8, v11, :cond_a

    .line 240
    .line 241
    invoke-virtual {v3}, Lw7/p;->a()I

    .line 242
    .line 243
    .line 244
    move-result v8

    .line 245
    invoke-interface {v4, v3, v8, v14}, Lo8/i0;->a(Lw7/p;II)V

    .line 246
    .line 247
    .line 248
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 249
    .line 250
    move-object/from16 v16, v2

    .line 251
    .line 252
    check-cast v16, Lo8/i0;

    .line 253
    .line 254
    const/16 v21, 0x0

    .line 255
    .line 256
    const/16 v22, 0x0

    .line 257
    .line 258
    const/16 v19, 0x1

    .line 259
    .line 260
    move/from16 v20, v8

    .line 261
    .line 262
    invoke-interface/range {v16 .. v22}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 263
    .line 264
    .line 265
    :goto_7
    move v14, v12

    .line 266
    goto :goto_8

    .line 267
    :cond_a
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 268
    .line 269
    .line 270
    move-result v8

    .line 271
    if-nez v8, :cond_b

    .line 272
    .line 273
    iget-boolean v11, v2, Lu8/a;->g:Z

    .line 274
    .line 275
    if-nez v11, :cond_b

    .line 276
    .line 277
    invoke-virtual {v3}, Lw7/p;->a()I

    .line 278
    .line 279
    .line 280
    move-result v8

    .line 281
    new-array v11, v8, [B

    .line 282
    .line 283
    invoke-virtual {v3, v11, v14, v8}, Lw7/p;->h([BII)V

    .line 284
    .line 285
    .line 286
    new-instance v3, Lm9/f;

    .line 287
    .line 288
    invoke-direct {v3, v8, v11}, Lm9/f;-><init>(I[B)V

    .line 289
    .line 290
    .line 291
    invoke-static {v3, v14}, Lo8/b;->n(Lm9/f;Z)Lo8/a;

    .line 292
    .line 293
    .line 294
    move-result-object v3

    .line 295
    new-instance v8, Lt7/n;

    .line 296
    .line 297
    invoke-direct {v8}, Lt7/n;-><init>()V

    .line 298
    .line 299
    .line 300
    const-string v15, "video/x-flv"

    .line 301
    .line 302
    invoke-static {v15}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v15

    .line 306
    iput-object v15, v8, Lt7/n;->l:Ljava/lang/String;

    .line 307
    .line 308
    const-string v15, "audio/mp4a-latm"

    .line 309
    .line 310
    invoke-static {v15}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v15

    .line 314
    iput-object v15, v8, Lt7/n;->m:Ljava/lang/String;

    .line 315
    .line 316
    iget-object v15, v3, Lo8/a;->a:Ljava/lang/String;

    .line 317
    .line 318
    iput-object v15, v8, Lt7/n;->j:Ljava/lang/String;

    .line 319
    .line 320
    iget v15, v3, Lo8/a;->c:I

    .line 321
    .line 322
    iput v15, v8, Lt7/n;->E:I

    .line 323
    .line 324
    iget v3, v3, Lo8/a;->b:I

    .line 325
    .line 326
    iput v3, v8, Lt7/n;->F:I

    .line 327
    .line 328
    invoke-static {v11}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 329
    .line 330
    .line 331
    move-result-object v3

    .line 332
    iput-object v3, v8, Lt7/n;->p:Ljava/util/List;

    .line 333
    .line 334
    invoke-static {v8, v4}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 335
    .line 336
    .line 337
    iput-boolean v12, v2, Lu8/a;->g:Z

    .line 338
    .line 339
    goto :goto_8

    .line 340
    :cond_b
    iget v11, v2, Lu8/a;->h:I

    .line 341
    .line 342
    const/16 v15, 0xa

    .line 343
    .line 344
    if-ne v11, v15, :cond_c

    .line 345
    .line 346
    if-ne v8, v12, :cond_d

    .line 347
    .line 348
    :cond_c
    invoke-virtual {v3}, Lw7/p;->a()I

    .line 349
    .line 350
    .line 351
    move-result v8

    .line 352
    invoke-interface {v4, v3, v8, v14}, Lo8/i0;->a(Lw7/p;II)V

    .line 353
    .line 354
    .line 355
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 356
    .line 357
    move-object/from16 v16, v2

    .line 358
    .line 359
    check-cast v16, Lo8/i0;

    .line 360
    .line 361
    const/16 v21, 0x0

    .line 362
    .line 363
    const/16 v22, 0x0

    .line 364
    .line 365
    const/16 v19, 0x1

    .line 366
    .line 367
    move/from16 v20, v8

    .line 368
    .line 369
    invoke-interface/range {v16 .. v22}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 370
    .line 371
    .line 372
    goto :goto_7

    .line 373
    :cond_d
    :goto_8
    move v2, v7

    .line 374
    move-wide/from16 v19, v9

    .line 375
    .line 376
    goto/16 :goto_11

    .line 377
    .line 378
    :cond_e
    const/16 p2, 0x0

    .line 379
    .line 380
    if-ne v2, v3, :cond_19

    .line 381
    .line 382
    iget-object v3, v0, Lu8/b;->p:Lu8/d;

    .line 383
    .line 384
    if-eqz v3, :cond_19

    .line 385
    .line 386
    iget-boolean v2, v0, Lu8/b;->n:Z

    .line 387
    .line 388
    if-nez v2, :cond_f

    .line 389
    .line 390
    iget-object v2, v0, Lu8/b;->f:Lo8/q;

    .line 391
    .line 392
    new-instance v3, Lo8/t;

    .line 393
    .line 394
    invoke-direct {v3, v9, v10}, Lo8/t;-><init>(J)V

    .line 395
    .line 396
    .line 397
    invoke-interface {v2, v3}, Lo8/q;->c(Lo8/c0;)V

    .line 398
    .line 399
    .line 400
    iput-boolean v7, v0, Lu8/b;->n:Z

    .line 401
    .line 402
    :cond_f
    iget-object v2, v0, Lu8/b;->p:Lu8/d;

    .line 403
    .line 404
    invoke-virtual/range {p0 .. p1}, Lu8/b;->e(Lo8/p;)Lw7/p;

    .line 405
    .line 406
    .line 407
    move-result-object v3

    .line 408
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 409
    .line 410
    .line 411
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 412
    .line 413
    .line 414
    move-result v4

    .line 415
    shr-int/lit8 v8, v4, 0x4

    .line 416
    .line 417
    and-int/lit8 v8, v8, 0xf

    .line 418
    .line 419
    and-int/lit8 v4, v4, 0xf

    .line 420
    .line 421
    const/4 v11, 0x7

    .line 422
    if-ne v4, v11, :cond_18

    .line 423
    .line 424
    iput v8, v2, Lu8/d;->k:I

    .line 425
    .line 426
    const/4 v4, 0x5

    .line 427
    if-eq v8, v4, :cond_10

    .line 428
    .line 429
    const/4 v4, 0x1

    .line 430
    goto :goto_9

    .line 431
    :cond_10
    const/4 v4, 0x0

    .line 432
    :goto_9
    if-eqz v4, :cond_16

    .line 433
    .line 434
    iget-object v4, v2, Lu8/d;->f:Lw7/p;

    .line 435
    .line 436
    iget-object v8, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 437
    .line 438
    check-cast v8, Lo8/i0;

    .line 439
    .line 440
    iget-object v11, v2, Lu8/d;->g:Lw7/p;

    .line 441
    .line 442
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 443
    .line 444
    .line 445
    move-result v12

    .line 446
    iget-object v14, v3, Lw7/p;->a:[B

    .line 447
    .line 448
    iget v15, v3, Lw7/p;->b:I

    .line 449
    .line 450
    move-wide/from16 v19, v9

    .line 451
    .line 452
    add-int/lit8 v9, v15, 0x1

    .line 453
    .line 454
    iput v9, v3, Lw7/p;->b:I

    .line 455
    .line 456
    aget-byte v10, v14, v15

    .line 457
    .line 458
    and-int/lit16 v10, v10, 0xff

    .line 459
    .line 460
    shl-int/lit8 v10, v10, 0x18

    .line 461
    .line 462
    shr-int/lit8 v10, v10, 0x8

    .line 463
    .line 464
    add-int/lit8 v5, v15, 0x2

    .line 465
    .line 466
    iput v5, v3, Lw7/p;->b:I

    .line 467
    .line 468
    aget-byte v9, v14, v9

    .line 469
    .line 470
    and-int/lit16 v9, v9, 0xff

    .line 471
    .line 472
    shl-int/lit8 v9, v9, 0x8

    .line 473
    .line 474
    or-int/2addr v9, v10

    .line 475
    add-int/lit8 v15, v15, 0x3

    .line 476
    .line 477
    iput v15, v3, Lw7/p;->b:I

    .line 478
    .line 479
    aget-byte v5, v14, v5

    .line 480
    .line 481
    and-int/lit16 v5, v5, 0xff

    .line 482
    .line 483
    or-int/2addr v5, v9

    .line 484
    int-to-long v9, v5

    .line 485
    const-wide/16 v14, 0x3e8

    .line 486
    .line 487
    mul-long/2addr v9, v14

    .line 488
    add-long v22, v9, v17

    .line 489
    .line 490
    const/4 v5, 0x0

    .line 491
    const/4 v9, 0x1

    .line 492
    if-nez v12, :cond_11

    .line 493
    .line 494
    iget-boolean v10, v2, Lu8/d;->i:Z

    .line 495
    .line 496
    if-nez v10, :cond_11

    .line 497
    .line 498
    new-instance v4, Lw7/p;

    .line 499
    .line 500
    invoke-virtual {v3}, Lw7/p;->a()I

    .line 501
    .line 502
    .line 503
    move-result v10

    .line 504
    new-array v10, v10, [B

    .line 505
    .line 506
    invoke-direct {v4, v10}, Lw7/p;-><init>([B)V

    .line 507
    .line 508
    .line 509
    invoke-virtual {v3}, Lw7/p;->a()I

    .line 510
    .line 511
    .line 512
    move-result v11

    .line 513
    invoke-virtual {v3, v10, v5, v11}, Lw7/p;->h([BII)V

    .line 514
    .line 515
    .line 516
    invoke-static {v4}, Lo8/d;->a(Lw7/p;)Lo8/d;

    .line 517
    .line 518
    .line 519
    move-result-object v3

    .line 520
    iget v4, v3, Lo8/d;->b:I

    .line 521
    .line 522
    iput v4, v2, Lu8/d;->h:I

    .line 523
    .line 524
    new-instance v4, Lt7/n;

    .line 525
    .line 526
    invoke-direct {v4}, Lt7/n;-><init>()V

    .line 527
    .line 528
    .line 529
    const-string v10, "video/x-flv"

    .line 530
    .line 531
    invoke-static {v10}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 532
    .line 533
    .line 534
    move-result-object v10

    .line 535
    iput-object v10, v4, Lt7/n;->l:Ljava/lang/String;

    .line 536
    .line 537
    const-string v10, "video/avc"

    .line 538
    .line 539
    invoke-static {v10}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 540
    .line 541
    .line 542
    move-result-object v10

    .line 543
    iput-object v10, v4, Lt7/n;->m:Ljava/lang/String;

    .line 544
    .line 545
    iget-object v10, v3, Lo8/d;->l:Ljava/lang/String;

    .line 546
    .line 547
    iput-object v10, v4, Lt7/n;->j:Ljava/lang/String;

    .line 548
    .line 549
    iget v10, v3, Lo8/d;->c:I

    .line 550
    .line 551
    iput v10, v4, Lt7/n;->t:I

    .line 552
    .line 553
    iget v10, v3, Lo8/d;->d:I

    .line 554
    .line 555
    iput v10, v4, Lt7/n;->u:I

    .line 556
    .line 557
    iget v10, v3, Lo8/d;->k:F

    .line 558
    .line 559
    iput v10, v4, Lt7/n;->z:F

    .line 560
    .line 561
    iget-object v3, v3, Lo8/d;->a:Ljava/util/ArrayList;

    .line 562
    .line 563
    iput-object v3, v4, Lt7/n;->p:Ljava/util/List;

    .line 564
    .line 565
    invoke-static {v4, v8}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 566
    .line 567
    .line 568
    iput-boolean v9, v2, Lu8/d;->i:Z

    .line 569
    .line 570
    goto :goto_c

    .line 571
    :cond_11
    if-ne v12, v9, :cond_15

    .line 572
    .line 573
    iget-boolean v10, v2, Lu8/d;->i:Z

    .line 574
    .line 575
    if-eqz v10, :cond_15

    .line 576
    .line 577
    iget v10, v2, Lu8/d;->k:I

    .line 578
    .line 579
    if-ne v10, v9, :cond_12

    .line 580
    .line 581
    move/from16 v24, v9

    .line 582
    .line 583
    goto :goto_a

    .line 584
    :cond_12
    move/from16 v24, v5

    .line 585
    .line 586
    :goto_a
    iget-boolean v10, v2, Lu8/d;->j:Z

    .line 587
    .line 588
    if-nez v10, :cond_13

    .line 589
    .line 590
    if-nez v24, :cond_13

    .line 591
    .line 592
    goto :goto_c

    .line 593
    :cond_13
    iget-object v10, v11, Lw7/p;->a:[B

    .line 594
    .line 595
    aput-byte v5, v10, v5

    .line 596
    .line 597
    aput-byte v5, v10, v9

    .line 598
    .line 599
    const/4 v12, 0x2

    .line 600
    aput-byte v5, v10, v12

    .line 601
    .line 602
    iget v10, v2, Lu8/d;->h:I

    .line 603
    .line 604
    const/4 v12, 0x4

    .line 605
    rsub-int/lit8 v10, v10, 0x4

    .line 606
    .line 607
    move/from16 v25, v5

    .line 608
    .line 609
    :goto_b
    invoke-virtual {v3}, Lw7/p;->a()I

    .line 610
    .line 611
    .line 612
    move-result v14

    .line 613
    if-lez v14, :cond_14

    .line 614
    .line 615
    iget-object v14, v11, Lw7/p;->a:[B

    .line 616
    .line 617
    iget v15, v2, Lu8/d;->h:I

    .line 618
    .line 619
    invoke-virtual {v3, v14, v10, v15}, Lw7/p;->h([BII)V

    .line 620
    .line 621
    .line 622
    invoke-virtual {v11, v5}, Lw7/p;->I(I)V

    .line 623
    .line 624
    .line 625
    invoke-virtual {v11}, Lw7/p;->A()I

    .line 626
    .line 627
    .line 628
    move-result v14

    .line 629
    invoke-virtual {v4, v5}, Lw7/p;->I(I)V

    .line 630
    .line 631
    .line 632
    invoke-interface {v8, v4, v12, v5}, Lo8/i0;->a(Lw7/p;II)V

    .line 633
    .line 634
    .line 635
    add-int/lit8 v25, v25, 0x4

    .line 636
    .line 637
    invoke-interface {v8, v3, v14, v5}, Lo8/i0;->a(Lw7/p;II)V

    .line 638
    .line 639
    .line 640
    add-int v25, v25, v14

    .line 641
    .line 642
    goto :goto_b

    .line 643
    :cond_14
    iget-object v3, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 644
    .line 645
    move-object/from16 v21, v3

    .line 646
    .line 647
    check-cast v21, Lo8/i0;

    .line 648
    .line 649
    const/16 v26, 0x0

    .line 650
    .line 651
    const/16 v27, 0x0

    .line 652
    .line 653
    invoke-interface/range {v21 .. v27}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 654
    .line 655
    .line 656
    iput-boolean v9, v2, Lu8/d;->j:Z

    .line 657
    .line 658
    move v5, v9

    .line 659
    :cond_15
    :goto_c
    if-eqz v5, :cond_17

    .line 660
    .line 661
    move v2, v7

    .line 662
    goto :goto_d

    .line 663
    :cond_16
    move-wide/from16 v19, v9

    .line 664
    .line 665
    :cond_17
    move/from16 v2, p2

    .line 666
    .line 667
    :goto_d
    move v14, v2

    .line 668
    :goto_e
    move v2, v7

    .line 669
    goto/16 :goto_11

    .line 670
    .line 671
    :cond_18
    new-instance v0, Lh8/f1;

    .line 672
    .line 673
    const-string v1, "Video format not supported: "

    .line 674
    .line 675
    invoke-static {v4, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 676
    .line 677
    .line 678
    move-result-object v1

    .line 679
    invoke-direct {v0, v1}, Lh8/f1;-><init>(Ljava/lang/String;)V

    .line 680
    .line 681
    .line 682
    throw v0

    .line 683
    :cond_19
    move-wide/from16 v19, v9

    .line 684
    .line 685
    const/16 v3, 0x12

    .line 686
    .line 687
    if-ne v2, v3, :cond_22

    .line 688
    .line 689
    iget-boolean v2, v0, Lu8/b;->n:Z

    .line 690
    .line 691
    if-nez v2, :cond_22

    .line 692
    .line 693
    invoke-virtual/range {p0 .. p1}, Lu8/b;->e(Lo8/p;)Lw7/p;

    .line 694
    .line 695
    .line 696
    move-result-object v2

    .line 697
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 698
    .line 699
    .line 700
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 701
    .line 702
    .line 703
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 704
    .line 705
    .line 706
    move-result v3

    .line 707
    const/4 v4, 0x2

    .line 708
    if-eq v3, v4, :cond_1a

    .line 709
    .line 710
    goto/16 :goto_10

    .line 711
    .line 712
    :cond_1a
    invoke-static {v2}, Lu8/c;->d0(Lw7/p;)Ljava/lang/String;

    .line 713
    .line 714
    .line 715
    move-result-object v3

    .line 716
    const-string v4, "onMetaData"

    .line 717
    .line 718
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 719
    .line 720
    .line 721
    move-result v3

    .line 722
    if-nez v3, :cond_1b

    .line 723
    .line 724
    goto/16 :goto_10

    .line 725
    .line 726
    :cond_1b
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 727
    .line 728
    .line 729
    move-result v3

    .line 730
    if-nez v3, :cond_1c

    .line 731
    .line 732
    goto/16 :goto_10

    .line 733
    .line 734
    :cond_1c
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 735
    .line 736
    .line 737
    move-result v3

    .line 738
    const/16 v4, 0x8

    .line 739
    .line 740
    if-eq v3, v4, :cond_1d

    .line 741
    .line 742
    goto/16 :goto_10

    .line 743
    .line 744
    :cond_1d
    invoke-static {v2}, Lu8/c;->c0(Lw7/p;)Ljava/util/HashMap;

    .line 745
    .line 746
    .line 747
    move-result-object v2

    .line 748
    const-string v3, "duration"

    .line 749
    .line 750
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 751
    .line 752
    .line 753
    move-result-object v3

    .line 754
    instance-of v4, v3, Ljava/lang/Double;

    .line 755
    .line 756
    const-wide v8, 0x412e848000000000L    # 1000000.0

    .line 757
    .line 758
    .line 759
    .line 760
    .line 761
    if-eqz v4, :cond_1e

    .line 762
    .line 763
    check-cast v3, Ljava/lang/Double;

    .line 764
    .line 765
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 766
    .line 767
    .line 768
    move-result-wide v3

    .line 769
    const-wide/16 v10, 0x0

    .line 770
    .line 771
    cmpl-double v5, v3, v10

    .line 772
    .line 773
    if-lez v5, :cond_1e

    .line 774
    .line 775
    mul-double/2addr v3, v8

    .line 776
    double-to-long v3, v3

    .line 777
    iput-wide v3, v13, Lu8/c;->f:J

    .line 778
    .line 779
    :cond_1e
    const-string v3, "keyframes"

    .line 780
    .line 781
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 782
    .line 783
    .line 784
    move-result-object v2

    .line 785
    instance-of v3, v2, Ljava/util/Map;

    .line 786
    .line 787
    if-eqz v3, :cond_20

    .line 788
    .line 789
    check-cast v2, Ljava/util/Map;

    .line 790
    .line 791
    const-string v3, "filepositions"

    .line 792
    .line 793
    invoke-interface {v2, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    move-result-object v3

    .line 797
    const-string v4, "times"

    .line 798
    .line 799
    invoke-interface {v2, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 800
    .line 801
    .line 802
    move-result-object v2

    .line 803
    instance-of v4, v3, Ljava/util/List;

    .line 804
    .line 805
    if-eqz v4, :cond_20

    .line 806
    .line 807
    instance-of v4, v2, Ljava/util/List;

    .line 808
    .line 809
    if-eqz v4, :cond_20

    .line 810
    .line 811
    check-cast v3, Ljava/util/List;

    .line 812
    .line 813
    check-cast v2, Ljava/util/List;

    .line 814
    .line 815
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 816
    .line 817
    .line 818
    move-result v4

    .line 819
    new-array v5, v4, [J

    .line 820
    .line 821
    iput-object v5, v13, Lu8/c;->g:[J

    .line 822
    .line 823
    new-array v5, v4, [J

    .line 824
    .line 825
    iput-object v5, v13, Lu8/c;->h:[J

    .line 826
    .line 827
    const/4 v5, 0x0

    .line 828
    move v10, v5

    .line 829
    :goto_f
    if-ge v10, v4, :cond_20

    .line 830
    .line 831
    invoke-interface {v3, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 832
    .line 833
    .line 834
    move-result-object v11

    .line 835
    invoke-interface {v2, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 836
    .line 837
    .line 838
    move-result-object v12

    .line 839
    instance-of v14, v12, Ljava/lang/Double;

    .line 840
    .line 841
    if-eqz v14, :cond_1f

    .line 842
    .line 843
    instance-of v14, v11, Ljava/lang/Double;

    .line 844
    .line 845
    if-eqz v14, :cond_1f

    .line 846
    .line 847
    iget-object v14, v13, Lu8/c;->g:[J

    .line 848
    .line 849
    check-cast v12, Ljava/lang/Double;

    .line 850
    .line 851
    invoke-virtual {v12}, Ljava/lang/Double;->doubleValue()D

    .line 852
    .line 853
    .line 854
    move-result-wide v17

    .line 855
    move-wide/from16 v21, v8

    .line 856
    .line 857
    mul-double v8, v17, v21

    .line 858
    .line 859
    double-to-long v8, v8

    .line 860
    aput-wide v8, v14, v10

    .line 861
    .line 862
    iget-object v8, v13, Lu8/c;->h:[J

    .line 863
    .line 864
    check-cast v11, Ljava/lang/Double;

    .line 865
    .line 866
    invoke-virtual {v11}, Ljava/lang/Double;->longValue()J

    .line 867
    .line 868
    .line 869
    move-result-wide v11

    .line 870
    aput-wide v11, v8, v10

    .line 871
    .line 872
    add-int/lit8 v10, v10, 0x1

    .line 873
    .line 874
    move-wide/from16 v8, v21

    .line 875
    .line 876
    goto :goto_f

    .line 877
    :cond_1f
    new-array v2, v5, [J

    .line 878
    .line 879
    iput-object v2, v13, Lu8/c;->g:[J

    .line 880
    .line 881
    new-array v2, v5, [J

    .line 882
    .line 883
    iput-object v2, v13, Lu8/c;->h:[J

    .line 884
    .line 885
    :cond_20
    :goto_10
    iget-wide v2, v13, Lu8/c;->f:J

    .line 886
    .line 887
    cmp-long v4, v2, v19

    .line 888
    .line 889
    if-eqz v4, :cond_21

    .line 890
    .line 891
    iget-object v4, v0, Lu8/b;->f:Lo8/q;

    .line 892
    .line 893
    new-instance v5, Lo8/z;

    .line 894
    .line 895
    iget-object v8, v13, Lu8/c;->h:[J

    .line 896
    .line 897
    iget-object v9, v13, Lu8/c;->g:[J

    .line 898
    .line 899
    invoke-direct {v5, v2, v3, v8, v9}, Lo8/z;-><init>(J[J[J)V

    .line 900
    .line 901
    .line 902
    invoke-interface {v4, v5}, Lo8/q;->c(Lo8/c0;)V

    .line 903
    .line 904
    .line 905
    iput-boolean v7, v0, Lu8/b;->n:Z

    .line 906
    .line 907
    :cond_21
    move/from16 v14, p2

    .line 908
    .line 909
    goto/16 :goto_e

    .line 910
    .line 911
    :cond_22
    iget v2, v0, Lu8/b;->l:I

    .line 912
    .line 913
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 914
    .line 915
    .line 916
    move/from16 v2, p2

    .line 917
    .line 918
    move v14, v2

    .line 919
    :goto_11
    iget-boolean v3, v0, Lu8/b;->h:Z

    .line 920
    .line 921
    if-nez v3, :cond_24

    .line 922
    .line 923
    if-eqz v14, :cond_24

    .line 924
    .line 925
    iput-boolean v7, v0, Lu8/b;->h:Z

    .line 926
    .line 927
    iget-wide v3, v13, Lu8/c;->f:J

    .line 928
    .line 929
    cmp-long v3, v3, v19

    .line 930
    .line 931
    if-nez v3, :cond_23

    .line 932
    .line 933
    iget-wide v3, v0, Lu8/b;->m:J

    .line 934
    .line 935
    neg-long v11, v3

    .line 936
    goto :goto_12

    .line 937
    :cond_23
    const-wide/16 v11, 0x0

    .line 938
    .line 939
    :goto_12
    iput-wide v11, v0, Lu8/b;->i:J

    .line 940
    .line 941
    :cond_24
    iput v6, v0, Lu8/b;->j:I

    .line 942
    .line 943
    const/4 v3, 0x2

    .line 944
    iput v3, v0, Lu8/b;->g:I

    .line 945
    .line 946
    if-eqz v2, :cond_0

    .line 947
    .line 948
    return p2

    .line 949
    :cond_25
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 950
    .line 951
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 952
    .line 953
    .line 954
    throw v0

    .line 955
    :cond_26
    const/16 p2, 0x0

    .line 956
    .line 957
    iget-object v2, v0, Lu8/b;->c:Lw7/p;

    .line 958
    .line 959
    iget-object v3, v2, Lw7/p;->a:[B

    .line 960
    .line 961
    const/16 v4, 0xb

    .line 962
    .line 963
    move/from16 v5, p2

    .line 964
    .line 965
    invoke-interface {v1, v3, v5, v4, v7}, Lo8/p;->f([BIIZ)Z

    .line 966
    .line 967
    .line 968
    move-result v3

    .line 969
    if-nez v3, :cond_27

    .line 970
    .line 971
    goto :goto_13

    .line 972
    :cond_27
    invoke-virtual {v2, v5}, Lw7/p;->I(I)V

    .line 973
    .line 974
    .line 975
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 976
    .line 977
    .line 978
    move-result v3

    .line 979
    iput v3, v0, Lu8/b;->k:I

    .line 980
    .line 981
    invoke-virtual {v2}, Lw7/p;->z()I

    .line 982
    .line 983
    .line 984
    move-result v3

    .line 985
    iput v3, v0, Lu8/b;->l:I

    .line 986
    .line 987
    invoke-virtual {v2}, Lw7/p;->z()I

    .line 988
    .line 989
    .line 990
    move-result v3

    .line 991
    int-to-long v3, v3

    .line 992
    iput-wide v3, v0, Lu8/b;->m:J

    .line 993
    .line 994
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 995
    .line 996
    .line 997
    move-result v3

    .line 998
    shl-int/lit8 v3, v3, 0x18

    .line 999
    .line 1000
    int-to-long v3, v3

    .line 1001
    iget-wide v7, v0, Lu8/b;->m:J

    .line 1002
    .line 1003
    or-long/2addr v3, v7

    .line 1004
    const-wide/16 v7, 0x3e8

    .line 1005
    .line 1006
    mul-long/2addr v3, v7

    .line 1007
    iput-wide v3, v0, Lu8/b;->m:J

    .line 1008
    .line 1009
    invoke-virtual {v2, v9}, Lw7/p;->J(I)V

    .line 1010
    .line 1011
    .line 1012
    iput v6, v0, Lu8/b;->g:I

    .line 1013
    .line 1014
    goto/16 :goto_0

    .line 1015
    .line 1016
    :cond_28
    iget v2, v0, Lu8/b;->j:I

    .line 1017
    .line 1018
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 1019
    .line 1020
    .line 1021
    const/4 v5, 0x0

    .line 1022
    iput v5, v0, Lu8/b;->j:I

    .line 1023
    .line 1024
    iput v9, v0, Lu8/b;->g:I

    .line 1025
    .line 1026
    goto/16 :goto_0

    .line 1027
    .line 1028
    :cond_29
    const/4 v5, 0x0

    .line 1029
    iget-object v2, v0, Lu8/b;->b:Lw7/p;

    .line 1030
    .line 1031
    iget-object v8, v2, Lw7/p;->a:[B

    .line 1032
    .line 1033
    invoke-interface {v1, v8, v5, v3, v7}, Lo8/p;->f([BIIZ)Z

    .line 1034
    .line 1035
    .line 1036
    move-result v8

    .line 1037
    if-nez v8, :cond_2a

    .line 1038
    .line 1039
    :goto_13
    const/4 v0, -0x1

    .line 1040
    return v0

    .line 1041
    :cond_2a
    invoke-virtual {v2, v5}, Lw7/p;->I(I)V

    .line 1042
    .line 1043
    .line 1044
    invoke-virtual {v2, v6}, Lw7/p;->J(I)V

    .line 1045
    .line 1046
    .line 1047
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 1048
    .line 1049
    .line 1050
    move-result v6

    .line 1051
    and-int/lit8 v8, v6, 0x4

    .line 1052
    .line 1053
    if-eqz v8, :cond_2b

    .line 1054
    .line 1055
    move v8, v7

    .line 1056
    goto :goto_14

    .line 1057
    :cond_2b
    move v8, v5

    .line 1058
    :goto_14
    and-int/lit8 v6, v6, 0x1

    .line 1059
    .line 1060
    if-eqz v6, :cond_2c

    .line 1061
    .line 1062
    move v5, v7

    .line 1063
    :cond_2c
    if-eqz v8, :cond_2d

    .line 1064
    .line 1065
    iget-object v6, v0, Lu8/b;->o:Lu8/a;

    .line 1066
    .line 1067
    if-nez v6, :cond_2d

    .line 1068
    .line 1069
    new-instance v6, Lu8/a;

    .line 1070
    .line 1071
    iget-object v8, v0, Lu8/b;->f:Lo8/q;

    .line 1072
    .line 1073
    invoke-interface {v8, v4, v7}, Lo8/q;->q(II)Lo8/i0;

    .line 1074
    .line 1075
    .line 1076
    move-result-object v4

    .line 1077
    const/16 v7, 0x8

    .line 1078
    .line 1079
    invoke-direct {v6, v4, v7}, Lap0/o;-><init>(Ljava/lang/Object;I)V

    .line 1080
    .line 1081
    .line 1082
    iput-object v6, v0, Lu8/b;->o:Lu8/a;

    .line 1083
    .line 1084
    :cond_2d
    if-eqz v5, :cond_2e

    .line 1085
    .line 1086
    iget-object v4, v0, Lu8/b;->p:Lu8/d;

    .line 1087
    .line 1088
    if-nez v4, :cond_2e

    .line 1089
    .line 1090
    new-instance v4, Lu8/d;

    .line 1091
    .line 1092
    iget-object v5, v0, Lu8/b;->f:Lo8/q;

    .line 1093
    .line 1094
    const/4 v6, 0x2

    .line 1095
    invoke-interface {v5, v3, v6}, Lo8/q;->q(II)Lo8/i0;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v3

    .line 1099
    invoke-direct {v4, v3}, Lu8/d;-><init>(Lo8/i0;)V

    .line 1100
    .line 1101
    .line 1102
    iput-object v4, v0, Lu8/b;->p:Lu8/d;

    .line 1103
    .line 1104
    :cond_2e
    iget-object v3, v0, Lu8/b;->f:Lo8/q;

    .line 1105
    .line 1106
    invoke-interface {v3}, Lo8/q;->m()V

    .line 1107
    .line 1108
    .line 1109
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 1110
    .line 1111
    .line 1112
    move-result v2

    .line 1113
    add-int/lit8 v2, v2, -0x5

    .line 1114
    .line 1115
    iput v2, v0, Lu8/b;->j:I

    .line 1116
    .line 1117
    const/4 v3, 0x2

    .line 1118
    iput v3, v0, Lu8/b;->g:I

    .line 1119
    .line 1120
    goto/16 :goto_0
.end method

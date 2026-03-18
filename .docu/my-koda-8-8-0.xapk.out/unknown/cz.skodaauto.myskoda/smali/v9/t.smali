.class public final Lv9/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# instance fields
.field public final a:Lw7/p;

.field public final b:Lo8/a0;

.field public final c:Ljava/lang/String;

.field public final d:I

.field public final e:Ljava/lang/String;

.field public f:Lo8/i0;

.field public g:Ljava/lang/String;

.field public h:I

.field public i:I

.field public j:Z

.field public k:Z

.field public l:J

.field public m:I

.field public n:J


# direct methods
.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lv9/t;->h:I

    .line 6
    .line 7
    new-instance v1, Lw7/p;

    .line 8
    .line 9
    const/4 v2, 0x4

    .line 10
    invoke-direct {v1, v2}, Lw7/p;-><init>(I)V

    .line 11
    .line 12
    .line 13
    iput-object v1, p0, Lv9/t;->a:Lw7/p;

    .line 14
    .line 15
    iget-object v1, v1, Lw7/p;->a:[B

    .line 16
    .line 17
    const/4 v2, -0x1

    .line 18
    aput-byte v2, v1, v0

    .line 19
    .line 20
    new-instance v0, Lo8/a0;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lv9/t;->b:Lo8/a0;

    .line 26
    .line 27
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    iput-wide v0, p0, Lv9/t;->n:J

    .line 33
    .line 34
    iput-object p1, p0, Lv9/t;->c:Ljava/lang/String;

    .line 35
    .line 36
    iput p2, p0, Lv9/t;->d:I

    .line 37
    .line 38
    iput-object p3, p0, Lv9/t;->e:Ljava/lang/String;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final b(Lw7/p;)V
    .locals 12

    .line 1
    iget-object v0, p0, Lv9/t;->f:Lo8/i0;

    .line 2
    .line 3
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    :goto_0
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-lez v0, :cond_c

    .line 11
    .line 12
    iget v0, p0, Lv9/t;->h:I

    .line 13
    .line 14
    iget-object v1, p0, Lv9/t;->a:Lw7/p;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    const/4 v3, 0x2

    .line 18
    const/4 v4, 0x1

    .line 19
    if-eqz v0, :cond_7

    .line 20
    .line 21
    if-eq v0, v4, :cond_3

    .line 22
    .line 23
    if-ne v0, v3, :cond_2

    .line 24
    .line 25
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget v1, p0, Lv9/t;->m:I

    .line 30
    .line 31
    iget v3, p0, Lv9/t;->i:I

    .line 32
    .line 33
    sub-int/2addr v1, v3

    .line 34
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-object v1, p0, Lv9/t;->f:Lo8/i0;

    .line 39
    .line 40
    invoke-interface {v1, p1, v0, v2}, Lo8/i0;->a(Lw7/p;II)V

    .line 41
    .line 42
    .line 43
    iget v1, p0, Lv9/t;->i:I

    .line 44
    .line 45
    add-int/2addr v1, v0

    .line 46
    iput v1, p0, Lv9/t;->i:I

    .line 47
    .line 48
    iget v0, p0, Lv9/t;->m:I

    .line 49
    .line 50
    if-ge v1, v0, :cond_0

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    iget-wide v0, p0, Lv9/t;->n:J

    .line 54
    .line 55
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    cmp-long v0, v0, v5

    .line 61
    .line 62
    if-eqz v0, :cond_1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    move v4, v2

    .line 66
    :goto_1
    invoke-static {v4}, Lw7/a;->j(Z)V

    .line 67
    .line 68
    .line 69
    iget-object v5, p0, Lv9/t;->f:Lo8/i0;

    .line 70
    .line 71
    iget-wide v6, p0, Lv9/t;->n:J

    .line 72
    .line 73
    iget v9, p0, Lv9/t;->m:I

    .line 74
    .line 75
    const/4 v10, 0x0

    .line 76
    const/4 v11, 0x0

    .line 77
    const/4 v8, 0x1

    .line 78
    invoke-interface/range {v5 .. v11}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 79
    .line 80
    .line 81
    iget-wide v0, p0, Lv9/t;->n:J

    .line 82
    .line 83
    iget-wide v3, p0, Lv9/t;->l:J

    .line 84
    .line 85
    add-long/2addr v0, v3

    .line 86
    iput-wide v0, p0, Lv9/t;->n:J

    .line 87
    .line 88
    iput v2, p0, Lv9/t;->i:I

    .line 89
    .line 90
    iput v2, p0, Lv9/t;->h:I

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 94
    .line 95
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_3
    invoke-virtual {p1}, Lw7/p;->a()I

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    iget v5, p0, Lv9/t;->i:I

    .line 104
    .line 105
    const/4 v6, 0x4

    .line 106
    rsub-int/lit8 v5, v5, 0x4

    .line 107
    .line 108
    invoke-static {v0, v5}, Ljava/lang/Math;->min(II)I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    iget-object v5, v1, Lw7/p;->a:[B

    .line 113
    .line 114
    iget v7, p0, Lv9/t;->i:I

    .line 115
    .line 116
    invoke-virtual {p1, v5, v7, v0}, Lw7/p;->h([BII)V

    .line 117
    .line 118
    .line 119
    iget v5, p0, Lv9/t;->i:I

    .line 120
    .line 121
    add-int/2addr v5, v0

    .line 122
    iput v5, p0, Lv9/t;->i:I

    .line 123
    .line 124
    if-ge v5, v6, :cond_4

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_4
    invoke-virtual {v1, v2}, Lw7/p;->I(I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v1}, Lw7/p;->j()I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    iget-object v5, p0, Lv9/t;->b:Lo8/a0;

    .line 135
    .line 136
    invoke-virtual {v5, v0}, Lo8/a0;->a(I)Z

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    if-nez v0, :cond_5

    .line 141
    .line 142
    iput v2, p0, Lv9/t;->i:I

    .line 143
    .line 144
    iput v4, p0, Lv9/t;->h:I

    .line 145
    .line 146
    goto/16 :goto_0

    .line 147
    .line 148
    :cond_5
    iget v0, v5, Lo8/a0;->b:I

    .line 149
    .line 150
    iput v0, p0, Lv9/t;->m:I

    .line 151
    .line 152
    iget-boolean v0, p0, Lv9/t;->j:Z

    .line 153
    .line 154
    if-nez v0, :cond_6

    .line 155
    .line 156
    iget v0, v5, Lo8/a0;->f:I

    .line 157
    .line 158
    int-to-long v7, v0

    .line 159
    const-wide/32 v9, 0xf4240

    .line 160
    .line 161
    .line 162
    mul-long/2addr v7, v9

    .line 163
    iget v0, v5, Lo8/a0;->c:I

    .line 164
    .line 165
    int-to-long v9, v0

    .line 166
    div-long/2addr v7, v9

    .line 167
    iput-wide v7, p0, Lv9/t;->l:J

    .line 168
    .line 169
    new-instance v0, Lt7/n;

    .line 170
    .line 171
    invoke-direct {v0}, Lt7/n;-><init>()V

    .line 172
    .line 173
    .line 174
    iget-object v7, p0, Lv9/t;->g:Ljava/lang/String;

    .line 175
    .line 176
    iput-object v7, v0, Lt7/n;->a:Ljava/lang/String;

    .line 177
    .line 178
    iget-object v7, p0, Lv9/t;->e:Ljava/lang/String;

    .line 179
    .line 180
    invoke-static {v7}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v7

    .line 184
    iput-object v7, v0, Lt7/n;->l:Ljava/lang/String;

    .line 185
    .line 186
    iget-object v7, v5, Lo8/a0;->g:Ljava/io/Serializable;

    .line 187
    .line 188
    check-cast v7, Ljava/lang/String;

    .line 189
    .line 190
    invoke-static {v7}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v7

    .line 194
    iput-object v7, v0, Lt7/n;->m:Ljava/lang/String;

    .line 195
    .line 196
    const/16 v7, 0x1000

    .line 197
    .line 198
    iput v7, v0, Lt7/n;->n:I

    .line 199
    .line 200
    iget v7, v5, Lo8/a0;->d:I

    .line 201
    .line 202
    iput v7, v0, Lt7/n;->E:I

    .line 203
    .line 204
    iget v5, v5, Lo8/a0;->c:I

    .line 205
    .line 206
    iput v5, v0, Lt7/n;->F:I

    .line 207
    .line 208
    iget-object v5, p0, Lv9/t;->c:Ljava/lang/String;

    .line 209
    .line 210
    iput-object v5, v0, Lt7/n;->d:Ljava/lang/String;

    .line 211
    .line 212
    iget v5, p0, Lv9/t;->d:I

    .line 213
    .line 214
    iput v5, v0, Lt7/n;->f:I

    .line 215
    .line 216
    new-instance v5, Lt7/o;

    .line 217
    .line 218
    invoke-direct {v5, v0}, Lt7/o;-><init>(Lt7/n;)V

    .line 219
    .line 220
    .line 221
    iget-object v0, p0, Lv9/t;->f:Lo8/i0;

    .line 222
    .line 223
    invoke-interface {v0, v5}, Lo8/i0;->c(Lt7/o;)V

    .line 224
    .line 225
    .line 226
    iput-boolean v4, p0, Lv9/t;->j:Z

    .line 227
    .line 228
    :cond_6
    invoke-virtual {v1, v2}, Lw7/p;->I(I)V

    .line 229
    .line 230
    .line 231
    iget-object v0, p0, Lv9/t;->f:Lo8/i0;

    .line 232
    .line 233
    invoke-interface {v0, v1, v6, v2}, Lo8/i0;->a(Lw7/p;II)V

    .line 234
    .line 235
    .line 236
    iput v3, p0, Lv9/t;->h:I

    .line 237
    .line 238
    goto/16 :goto_0

    .line 239
    .line 240
    :cond_7
    iget-object v0, p1, Lw7/p;->a:[B

    .line 241
    .line 242
    iget v5, p1, Lw7/p;->b:I

    .line 243
    .line 244
    iget v6, p1, Lw7/p;->c:I

    .line 245
    .line 246
    :goto_2
    if-ge v5, v6, :cond_b

    .line 247
    .line 248
    aget-byte v7, v0, v5

    .line 249
    .line 250
    and-int/lit16 v8, v7, 0xff

    .line 251
    .line 252
    const/16 v9, 0xff

    .line 253
    .line 254
    if-ne v8, v9, :cond_8

    .line 255
    .line 256
    move v8, v4

    .line 257
    goto :goto_3

    .line 258
    :cond_8
    move v8, v2

    .line 259
    :goto_3
    iget-boolean v9, p0, Lv9/t;->k:Z

    .line 260
    .line 261
    if-eqz v9, :cond_9

    .line 262
    .line 263
    and-int/lit16 v7, v7, 0xe0

    .line 264
    .line 265
    const/16 v9, 0xe0

    .line 266
    .line 267
    if-ne v7, v9, :cond_9

    .line 268
    .line 269
    move v7, v4

    .line 270
    goto :goto_4

    .line 271
    :cond_9
    move v7, v2

    .line 272
    :goto_4
    iput-boolean v8, p0, Lv9/t;->k:Z

    .line 273
    .line 274
    if-eqz v7, :cond_a

    .line 275
    .line 276
    add-int/lit8 v6, v5, 0x1

    .line 277
    .line 278
    invoke-virtual {p1, v6}, Lw7/p;->I(I)V

    .line 279
    .line 280
    .line 281
    iput-boolean v2, p0, Lv9/t;->k:Z

    .line 282
    .line 283
    iget-object v1, v1, Lw7/p;->a:[B

    .line 284
    .line 285
    aget-byte v0, v0, v5

    .line 286
    .line 287
    aput-byte v0, v1, v4

    .line 288
    .line 289
    iput v3, p0, Lv9/t;->i:I

    .line 290
    .line 291
    iput v4, p0, Lv9/t;->h:I

    .line 292
    .line 293
    goto/16 :goto_0

    .line 294
    .line 295
    :cond_a
    add-int/lit8 v5, v5, 0x1

    .line 296
    .line 297
    goto :goto_2

    .line 298
    :cond_b
    invoke-virtual {p1, v6}, Lw7/p;->I(I)V

    .line 299
    .line 300
    .line 301
    goto/16 :goto_0

    .line 302
    .line 303
    :cond_c
    return-void
.end method

.method public final c()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lv9/t;->h:I

    .line 3
    .line 4
    iput v0, p0, Lv9/t;->i:I

    .line 5
    .line 6
    iput-boolean v0, p0, Lv9/t;->k:Z

    .line 7
    .line 8
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    iput-wide v0, p0, Lv9/t;->n:J

    .line 14
    .line 15
    return-void
.end method

.method public final d(Lo8/q;Lh11/h;)V
    .locals 1

    .line 1
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/lang/String;

    .line 10
    .line 11
    iput-object v0, p0, Lv9/t;->g:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 14
    .line 15
    .line 16
    iget p2, p2, Lh11/h;->f:I

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    invoke-interface {p1, p2, v0}, Lo8/q;->q(II)Lo8/i0;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lv9/t;->f:Lo8/i0;

    .line 24
    .line 25
    return-void
.end method

.method public final e(Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(IJ)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lv9/t;->n:J

    .line 2
    .line 3
    return-void
.end method

.class public final Lw8/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:Lw7/p;

.field public b:Lo8/q;

.field public c:I

.field public d:I

.field public e:I

.field public f:J

.field public g:Ld9/a;

.field public h:Lo8/p;

.field public i:Lg1/i3;

.field public j:Li9/m;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lw7/p;

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lw8/a;->a:Lw7/p;

    .line 11
    .line 12
    const-wide/16 v0, -0x1

    .line 13
    .line 14
    iput-wide v0, p0, Lw8/a;->f:J

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 5

    .line 1
    check-cast p1, Lo8/l;

    .line 2
    .line 3
    iget-object v0, p0, Lw8/a;->a:Lw7/p;

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    invoke-virtual {v0, v1}, Lw7/p;->F(I)V

    .line 7
    .line 8
    .line 9
    iget-object v2, v0, Lw7/p;->a:[B

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-virtual {p1, v2, v3, v1, v3}, Lo8/l;->b([BIIZ)Z

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const v4, 0xffd8

    .line 20
    .line 21
    .line 22
    if-eq v2, v4, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v0, v1}, Lw7/p;->F(I)V

    .line 26
    .line 27
    .line 28
    iget-object v2, v0, Lw7/p;->a:[B

    .line 29
    .line 30
    invoke-virtual {p1, v2, v3, v1, v3}, Lo8/l;->b([BIIZ)Z

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    iput v2, p0, Lw8/a;->d:I

    .line 38
    .line 39
    const v4, 0xffe0

    .line 40
    .line 41
    .line 42
    if-ne v2, v4, :cond_1

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Lw7/p;->F(I)V

    .line 45
    .line 46
    .line 47
    iget-object v2, v0, Lw7/p;->a:[B

    .line 48
    .line 49
    invoke-virtual {p1, v2, v3, v1, v3}, Lo8/l;->b([BIIZ)Z

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    sub-int/2addr v2, v1

    .line 57
    invoke-virtual {p1, v2, v3}, Lo8/l;->c(IZ)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, v1}, Lw7/p;->F(I)V

    .line 61
    .line 62
    .line 63
    iget-object v2, v0, Lw7/p;->a:[B

    .line 64
    .line 65
    invoke-virtual {p1, v2, v3, v1, v3}, Lo8/l;->b([BIIZ)Z

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    iput p1, p0, Lw8/a;->d:I

    .line 73
    .line 74
    :cond_1
    iget p0, p0, Lw8/a;->d:I

    .line 75
    .line 76
    const p1, 0xffe1

    .line 77
    .line 78
    .line 79
    if-ne p0, p1, :cond_2

    .line 80
    .line 81
    const/4 p0, 0x1

    .line 82
    return p0

    .line 83
    :cond_2
    :goto_0
    return v3
.end method

.method public final b()V
    .locals 0

    .line 1
    iget-object p0, p0, Lw8/a;->j:Li9/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lw8/a;->b:Lo8/q;

    .line 2
    .line 3
    return-void
.end method

.method public final d(JJ)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    iput p1, p0, Lw8/a;->c:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    iput-object p1, p0, Lw8/a;->j:Li9/m;

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget v0, p0, Lw8/a;->c:I

    .line 15
    .line 16
    const/4 v1, 0x5

    .line 17
    if-ne v0, v1, :cond_1

    .line 18
    .line 19
    iget-object p0, p0, Lw8/a;->j:Li9/m;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1, p2, p3, p4}, Li9/m;->d(JJ)V

    .line 25
    .line 26
    .line 27
    :cond_1
    return-void
.end method

.method public final e()V
    .locals 4

    .line 1
    iget-object v0, p0, Lw8/a;->b:Lo8/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-interface {v0}, Lo8/q;->m()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lw8/a;->b:Lo8/q;

    .line 10
    .line 11
    new-instance v1, Lo8/t;

    .line 12
    .line 13
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    invoke-direct {v1, v2, v3}, Lo8/t;-><init>(J)V

    .line 19
    .line 20
    .line 21
    invoke-interface {v0, v1}, Lo8/q;->c(Lo8/c0;)V

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x6

    .line 25
    iput v0, p0, Lw8/a;->c:I

    .line 26
    .line 27
    return-void
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget v3, v0, Lw8/a;->c:I

    .line 8
    .line 9
    const-wide/16 v4, -0x1

    .line 10
    .line 11
    iget-object v6, v0, Lw8/a;->a:Lw7/p;

    .line 12
    .line 13
    const/4 v7, 0x4

    .line 14
    const/4 v8, 0x2

    .line 15
    const/4 v9, 0x1

    .line 16
    const/4 v10, 0x0

    .line 17
    if-eqz v3, :cond_17

    .line 18
    .line 19
    if-eq v3, v9, :cond_16

    .line 20
    .line 21
    if-eq v3, v8, :cond_a

    .line 22
    .line 23
    const/4 v4, 0x5

    .line 24
    if-eq v3, v7, :cond_5

    .line 25
    .line 26
    if-eq v3, v4, :cond_1

    .line 27
    .line 28
    const/4 v0, 0x6

    .line 29
    if-ne v3, v0, :cond_0

    .line 30
    .line 31
    const/4 v0, -0x1

    .line 32
    return v0

    .line 33
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :cond_1
    iget-object v3, v0, Lw8/a;->i:Lg1/i3;

    .line 40
    .line 41
    if-eqz v3, :cond_2

    .line 42
    .line 43
    iget-object v3, v0, Lw8/a;->h:Lo8/p;

    .line 44
    .line 45
    if-eq v1, v3, :cond_3

    .line 46
    .line 47
    :cond_2
    iput-object v1, v0, Lw8/a;->h:Lo8/p;

    .line 48
    .line 49
    new-instance v3, Lg1/i3;

    .line 50
    .line 51
    iget-wide v4, v0, Lw8/a;->f:J

    .line 52
    .line 53
    invoke-direct {v3, v1, v4, v5}, Lg1/i3;-><init>(Lo8/p;J)V

    .line 54
    .line 55
    .line 56
    iput-object v3, v0, Lw8/a;->i:Lg1/i3;

    .line 57
    .line 58
    :cond_3
    iget-object v1, v0, Lw8/a;->j:Li9/m;

    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    iget-object v3, v0, Lw8/a;->i:Lg1/i3;

    .line 64
    .line 65
    invoke-virtual {v1, v3, v2}, Li9/m;->h(Lo8/p;Lo8/s;)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-ne v1, v9, :cond_4

    .line 70
    .line 71
    iget-wide v3, v2, Lo8/s;->a:J

    .line 72
    .line 73
    iget-wide v5, v0, Lw8/a;->f:J

    .line 74
    .line 75
    add-long/2addr v3, v5

    .line 76
    iput-wide v3, v2, Lo8/s;->a:J

    .line 77
    .line 78
    :cond_4
    return v1

    .line 79
    :cond_5
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 80
    .line 81
    .line 82
    move-result-wide v11

    .line 83
    iget-wide v13, v0, Lw8/a;->f:J

    .line 84
    .line 85
    cmp-long v3, v11, v13

    .line 86
    .line 87
    if-eqz v3, :cond_6

    .line 88
    .line 89
    iput-wide v13, v2, Lo8/s;->a:J

    .line 90
    .line 91
    return v9

    .line 92
    :cond_6
    iget-object v2, v6, Lw7/p;->a:[B

    .line 93
    .line 94
    invoke-interface {v1, v2, v10, v9, v9}, Lo8/p;->b([BIIZ)Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-nez v2, :cond_7

    .line 99
    .line 100
    invoke-virtual {v0}, Lw8/a;->e()V

    .line 101
    .line 102
    .line 103
    return v10

    .line 104
    :cond_7
    invoke-interface {v1}, Lo8/p;->e()V

    .line 105
    .line 106
    .line 107
    iget-object v2, v0, Lw8/a;->j:Li9/m;

    .line 108
    .line 109
    if-nez v2, :cond_8

    .line 110
    .line 111
    new-instance v2, Li9/m;

    .line 112
    .line 113
    sget-object v3, Ll9/h;->k1:Lwq/f;

    .line 114
    .line 115
    const/16 v5, 0x8

    .line 116
    .line 117
    invoke-direct {v2, v3, v5}, Li9/m;-><init>(Ll9/h;I)V

    .line 118
    .line 119
    .line 120
    iput-object v2, v0, Lw8/a;->j:Li9/m;

    .line 121
    .line 122
    :cond_8
    new-instance v2, Lg1/i3;

    .line 123
    .line 124
    iget-wide v5, v0, Lw8/a;->f:J

    .line 125
    .line 126
    invoke-direct {v2, v1, v5, v6}, Lg1/i3;-><init>(Lo8/p;J)V

    .line 127
    .line 128
    .line 129
    iput-object v2, v0, Lw8/a;->i:Lg1/i3;

    .line 130
    .line 131
    iget-object v1, v0, Lw8/a;->j:Li9/m;

    .line 132
    .line 133
    invoke-virtual {v1, v2}, Li9/m;->a(Lo8/p;)Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-eqz v1, :cond_9

    .line 138
    .line 139
    iget-object v1, v0, Lw8/a;->j:Li9/m;

    .line 140
    .line 141
    new-instance v2, Lg1/i3;

    .line 142
    .line 143
    iget-wide v5, v0, Lw8/a;->f:J

    .line 144
    .line 145
    iget-object v3, v0, Lw8/a;->b:Lo8/q;

    .line 146
    .line 147
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    const/16 v8, 0x9

    .line 151
    .line 152
    invoke-direct {v2, v5, v6, v3, v8}, Lg1/i3;-><init>(JLjava/lang/Object;I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v1, v2}, Li9/m;->c(Lo8/q;)V

    .line 156
    .line 157
    .line 158
    iget-object v1, v0, Lw8/a;->g:Ld9/a;

    .line 159
    .line 160
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    iget-object v2, v0, Lw8/a;->b:Lo8/q;

    .line 164
    .line 165
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    const/16 v3, 0x400

    .line 169
    .line 170
    invoke-interface {v2, v3, v7}, Lo8/q;->q(II)Lo8/i0;

    .line 171
    .line 172
    .line 173
    move-result-object v2

    .line 174
    new-instance v3, Lt7/n;

    .line 175
    .line 176
    invoke-direct {v3}, Lt7/n;-><init>()V

    .line 177
    .line 178
    .line 179
    const-string v5, "image/jpeg"

    .line 180
    .line 181
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v5

    .line 185
    iput-object v5, v3, Lt7/n;->l:Ljava/lang/String;

    .line 186
    .line 187
    new-instance v5, Lt7/c0;

    .line 188
    .line 189
    new-array v6, v9, [Lt7/b0;

    .line 190
    .line 191
    aput-object v1, v6, v10

    .line 192
    .line 193
    invoke-direct {v5, v6}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 194
    .line 195
    .line 196
    iput-object v5, v3, Lt7/n;->k:Lt7/c0;

    .line 197
    .line 198
    invoke-static {v3, v2}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 199
    .line 200
    .line 201
    iput v4, v0, Lw8/a;->c:I

    .line 202
    .line 203
    return v10

    .line 204
    :cond_9
    invoke-virtual {v0}, Lw8/a;->e()V

    .line 205
    .line 206
    .line 207
    return v10

    .line 208
    :cond_a
    iget v2, v0, Lw8/a;->d:I

    .line 209
    .line 210
    const v3, 0xffe1

    .line 211
    .line 212
    .line 213
    if-ne v2, v3, :cond_14

    .line 214
    .line 215
    new-instance v2, Lw7/p;

    .line 216
    .line 217
    iget v3, v0, Lw8/a;->e:I

    .line 218
    .line 219
    invoke-direct {v2, v3}, Lw7/p;-><init>(I)V

    .line 220
    .line 221
    .line 222
    iget-object v3, v2, Lw7/p;->a:[B

    .line 223
    .line 224
    iget v6, v0, Lw8/a;->e:I

    .line 225
    .line 226
    invoke-interface {v1, v3, v10, v6}, Lo8/p;->readFully([BII)V

    .line 227
    .line 228
    .line 229
    iget-object v3, v0, Lw8/a;->g:Ld9/a;

    .line 230
    .line 231
    if-nez v3, :cond_15

    .line 232
    .line 233
    const-string v3, "http://ns.adobe.com/xap/1.0/"

    .line 234
    .line 235
    invoke-virtual {v2}, Lw7/p;->r()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v6

    .line 239
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v3

    .line 243
    if-eqz v3, :cond_15

    .line 244
    .line 245
    invoke-virtual {v2}, Lw7/p;->r()Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v2

    .line 249
    if-eqz v2, :cond_15

    .line 250
    .line 251
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 252
    .line 253
    .line 254
    move-result-wide v6

    .line 255
    cmp-long v1, v6, v4

    .line 256
    .line 257
    if-nez v1, :cond_c

    .line 258
    .line 259
    :cond_b
    :goto_0
    const/4 v3, 0x0

    .line 260
    goto/16 :goto_5

    .line 261
    .line 262
    :cond_c
    :try_start_0
    invoke-static {v2}, Lw8/d;->a(Ljava/lang/String;)Lg1/i3;

    .line 263
    .line 264
    .line 265
    move-result-object v1
    :try_end_0
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Lt7/e0; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 266
    goto :goto_1

    .line 267
    :catch_0
    const-string v1, "MotionPhotoXmpParser"

    .line 268
    .line 269
    const-string v2, "Ignoring unexpected XMP metadata"

    .line 270
    .line 271
    invoke-static {v1, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    const/4 v1, 0x0

    .line 275
    :goto_1
    if-nez v1, :cond_d

    .line 276
    .line 277
    goto :goto_0

    .line 278
    :cond_d
    iget-object v2, v1, Lg1/i3;->f:Ljava/lang/Object;

    .line 279
    .line 280
    check-cast v2, Lhr/x0;

    .line 281
    .line 282
    iget v11, v2, Lhr/x0;->g:I

    .line 283
    .line 284
    if-ge v11, v8, :cond_e

    .line 285
    .line 286
    goto :goto_0

    .line 287
    :cond_e
    sub-int/2addr v11, v9

    .line 288
    move-wide v13, v4

    .line 289
    move-wide v15, v13

    .line 290
    move-wide/from16 v19, v15

    .line 291
    .line 292
    move-wide/from16 v21, v19

    .line 293
    .line 294
    move v8, v10

    .line 295
    :goto_2
    if-ltz v11, :cond_12

    .line 296
    .line 297
    invoke-virtual {v2, v11}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v9

    .line 301
    check-cast v9, Lw8/b;

    .line 302
    .line 303
    const-string v12, "video/mp4"

    .line 304
    .line 305
    iget-object v3, v9, Lw8/b;->a:Ljava/lang/String;

    .line 306
    .line 307
    invoke-virtual {v12, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    move-result v3

    .line 311
    or-int/2addr v3, v8

    .line 312
    if-nez v11, :cond_f

    .line 313
    .line 314
    iget-wide v8, v9, Lw8/b;->c:J

    .line 315
    .line 316
    sub-long/2addr v6, v8

    .line 317
    const-wide/16 v8, 0x0

    .line 318
    .line 319
    :goto_3
    move-wide/from16 v23, v8

    .line 320
    .line 321
    move-wide v8, v6

    .line 322
    move-wide/from16 v6, v23

    .line 323
    .line 324
    goto :goto_4

    .line 325
    :cond_f
    iget-wide v8, v9, Lw8/b;->b:J

    .line 326
    .line 327
    sub-long v8, v6, v8

    .line 328
    .line 329
    goto :goto_3

    .line 330
    :goto_4
    if-eqz v3, :cond_10

    .line 331
    .line 332
    cmp-long v12, v6, v8

    .line 333
    .line 334
    if-eqz v12, :cond_10

    .line 335
    .line 336
    sub-long v21, v8, v6

    .line 337
    .line 338
    move-wide/from16 v19, v6

    .line 339
    .line 340
    move v3, v10

    .line 341
    :cond_10
    if-nez v11, :cond_11

    .line 342
    .line 343
    move-wide v13, v6

    .line 344
    move-wide v15, v8

    .line 345
    :cond_11
    add-int/lit8 v11, v11, -0x1

    .line 346
    .line 347
    move v8, v3

    .line 348
    goto :goto_2

    .line 349
    :cond_12
    cmp-long v2, v19, v4

    .line 350
    .line 351
    if-eqz v2, :cond_b

    .line 352
    .line 353
    cmp-long v2, v21, v4

    .line 354
    .line 355
    if-eqz v2, :cond_b

    .line 356
    .line 357
    cmp-long v2, v13, v4

    .line 358
    .line 359
    if-eqz v2, :cond_b

    .line 360
    .line 361
    cmp-long v2, v15, v4

    .line 362
    .line 363
    if-nez v2, :cond_13

    .line 364
    .line 365
    goto :goto_0

    .line 366
    :cond_13
    new-instance v12, Ld9/a;

    .line 367
    .line 368
    iget-wide v1, v1, Lg1/i3;->e:J

    .line 369
    .line 370
    move-wide/from16 v17, v1

    .line 371
    .line 372
    invoke-direct/range {v12 .. v22}, Ld9/a;-><init>(JJJJJ)V

    .line 373
    .line 374
    .line 375
    move-object v3, v12

    .line 376
    :goto_5
    iput-object v3, v0, Lw8/a;->g:Ld9/a;

    .line 377
    .line 378
    if-eqz v3, :cond_15

    .line 379
    .line 380
    iget-wide v1, v3, Ld9/a;->d:J

    .line 381
    .line 382
    iput-wide v1, v0, Lw8/a;->f:J

    .line 383
    .line 384
    goto :goto_6

    .line 385
    :cond_14
    iget v2, v0, Lw8/a;->e:I

    .line 386
    .line 387
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 388
    .line 389
    .line 390
    :cond_15
    :goto_6
    iput v10, v0, Lw8/a;->c:I

    .line 391
    .line 392
    return v10

    .line 393
    :cond_16
    invoke-virtual {v6, v8}, Lw7/p;->F(I)V

    .line 394
    .line 395
    .line 396
    iget-object v2, v6, Lw7/p;->a:[B

    .line 397
    .line 398
    invoke-interface {v1, v2, v10, v8}, Lo8/p;->readFully([BII)V

    .line 399
    .line 400
    .line 401
    invoke-virtual {v6}, Lw7/p;->C()I

    .line 402
    .line 403
    .line 404
    move-result v1

    .line 405
    sub-int/2addr v1, v8

    .line 406
    iput v1, v0, Lw8/a;->e:I

    .line 407
    .line 408
    iput v8, v0, Lw8/a;->c:I

    .line 409
    .line 410
    return v10

    .line 411
    :cond_17
    invoke-virtual {v6, v8}, Lw7/p;->F(I)V

    .line 412
    .line 413
    .line 414
    iget-object v2, v6, Lw7/p;->a:[B

    .line 415
    .line 416
    invoke-interface {v1, v2, v10, v8}, Lo8/p;->readFully([BII)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v6}, Lw7/p;->C()I

    .line 420
    .line 421
    .line 422
    move-result v1

    .line 423
    iput v1, v0, Lw8/a;->d:I

    .line 424
    .line 425
    const v2, 0xffda

    .line 426
    .line 427
    .line 428
    if-ne v1, v2, :cond_19

    .line 429
    .line 430
    iget-wide v1, v0, Lw8/a;->f:J

    .line 431
    .line 432
    cmp-long v1, v1, v4

    .line 433
    .line 434
    if-eqz v1, :cond_18

    .line 435
    .line 436
    iput v7, v0, Lw8/a;->c:I

    .line 437
    .line 438
    return v10

    .line 439
    :cond_18
    invoke-virtual {v0}, Lw8/a;->e()V

    .line 440
    .line 441
    .line 442
    return v10

    .line 443
    :cond_19
    const v2, 0xffd0

    .line 444
    .line 445
    .line 446
    if-lt v1, v2, :cond_1a

    .line 447
    .line 448
    const v2, 0xffd9

    .line 449
    .line 450
    .line 451
    if-le v1, v2, :cond_1b

    .line 452
    .line 453
    :cond_1a
    const v2, 0xff01

    .line 454
    .line 455
    .line 456
    if-eq v1, v2, :cond_1b

    .line 457
    .line 458
    iput v9, v0, Lw8/a;->c:I

    .line 459
    .line 460
    :cond_1b
    return v10
.end method

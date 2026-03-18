.class public final Lh2/o9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lgy0/f;

.field public final synthetic g:I

.field public final synthetic h:Z

.field public final synthetic i:F

.field public final synthetic j:Lay0/a;


# direct methods
.method public constructor <init>(ZLay0/k;Lgy0/f;IZFLay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lh2/o9;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lh2/o9;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/o9;->f:Lgy0/f;

    .line 9
    .line 10
    iput p4, p0, Lh2/o9;->g:I

    .line 11
    .line 12
    iput-boolean p5, p0, Lh2/o9;->h:Z

    .line 13
    .line 14
    iput p6, p0, Lh2/o9;->i:F

    .line 15
    .line 16
    iput-object p7, p0, Lh2/o9;->j:Lay0/a;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Ln3/b;

    .line 2
    .line 3
    iget-object p1, p1, Ln3/b;->a:Landroid/view/KeyEvent;

    .line 4
    .line 5
    iget-boolean v0, p0, Lh2/o9;->d:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object v0, p0, Lh2/o9;->e:Lay0/k;

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_1
    invoke-static {p1}, Ln3/c;->c(Landroid/view/KeyEvent;)I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    const/4 v2, 0x2

    .line 24
    const/4 v3, 0x0

    .line 25
    const/4 v4, 0x1

    .line 26
    if-ne v1, v2, :cond_c

    .line 27
    .line 28
    iget-object v1, p0, Lh2/o9;->f:Lgy0/f;

    .line 29
    .line 30
    invoke-interface {v1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Ljava/lang/Number;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    invoke-interface {v1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 41
    .line 42
    .line 43
    move-result-object v5

    .line 44
    check-cast v5, Ljava/lang/Number;

    .line 45
    .line 46
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    sub-float/2addr v2, v5

    .line 51
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    iget v5, p0, Lh2/o9;->g:I

    .line 56
    .line 57
    if-lez v5, :cond_2

    .line 58
    .line 59
    add-int/2addr v5, v4

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    const/16 v5, 0x64

    .line 62
    .line 63
    :goto_0
    int-to-float v6, v5

    .line 64
    div-float/2addr v2, v6

    .line 65
    iget-boolean v6, p0, Lh2/o9;->h:Z

    .line 66
    .line 67
    if-eqz v6, :cond_3

    .line 68
    .line 69
    const/4 v6, -0x1

    .line 70
    goto :goto_1

    .line 71
    :cond_3
    move v6, v4

    .line 72
    :goto_1
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    invoke-static {p1}, Ljp/x1;->a(I)J

    .line 77
    .line 78
    .line 79
    move-result-wide v7

    .line 80
    sget-wide v9, Ln3/a;->d:J

    .line 81
    .line 82
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    iget p0, p0, Lh2/o9;->i:F

    .line 87
    .line 88
    if-eqz p1, :cond_5

    .line 89
    .line 90
    int-to-float p1, v6

    .line 91
    mul-float/2addr p1, v2

    .line 92
    add-float/2addr p1, p0

    .line 93
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-static {p0, v1}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    :cond_4
    :goto_2
    move v3, v4

    .line 105
    goto/16 :goto_3

    .line 106
    .line 107
    :cond_5
    sget-wide v9, Ln3/a;->e:J

    .line 108
    .line 109
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    if-eqz p1, :cond_6

    .line 114
    .line 115
    int-to-float p1, v6

    .line 116
    mul-float/2addr p1, v2

    .line 117
    sub-float/2addr p0, p1

    .line 118
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-static {p0, v1}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_6
    sget-wide v9, Ln3/a;->g:J

    .line 131
    .line 132
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    if-eqz p1, :cond_7

    .line 137
    .line 138
    int-to-float p1, v6

    .line 139
    mul-float/2addr p1, v2

    .line 140
    add-float/2addr p1, p0

    .line 141
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    invoke-static {p0, v1}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_7
    sget-wide v9, Ln3/a;->f:J

    .line 154
    .line 155
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 156
    .line 157
    .line 158
    move-result p1

    .line 159
    if-eqz p1, :cond_8

    .line 160
    .line 161
    int-to-float p1, v6

    .line 162
    mul-float/2addr p1, v2

    .line 163
    sub-float/2addr p0, p1

    .line 164
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    invoke-static {p0, v1}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_8
    sget-wide v9, Ln3/a;->m:J

    .line 177
    .line 178
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 179
    .line 180
    .line 181
    move-result p1

    .line 182
    if-eqz p1, :cond_9

    .line 183
    .line 184
    invoke-interface {v1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_9
    sget-wide v9, Ln3/a;->n:J

    .line 193
    .line 194
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 195
    .line 196
    .line 197
    move-result p1

    .line 198
    if-eqz p1, :cond_a

    .line 199
    .line 200
    invoke-interface {v1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    goto :goto_2

    .line 208
    :cond_a
    sget-wide v9, Ln3/a;->o:J

    .line 209
    .line 210
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 211
    .line 212
    .line 213
    move-result p1

    .line 214
    const/16 v6, 0xa

    .line 215
    .line 216
    if-eqz p1, :cond_b

    .line 217
    .line 218
    div-int/2addr v5, v6

    .line 219
    invoke-static {v5, v4, v6}, Lkp/r9;->e(III)I

    .line 220
    .line 221
    .line 222
    move-result p1

    .line 223
    int-to-float p1, p1

    .line 224
    mul-float/2addr p1, v2

    .line 225
    sub-float/2addr p0, p1

    .line 226
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    invoke-static {p0, v1}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    goto/16 :goto_2

    .line 238
    .line 239
    :cond_b
    sget-wide v9, Ln3/a;->p:J

    .line 240
    .line 241
    invoke-static {v7, v8, v9, v10}, Ln3/a;->a(JJ)Z

    .line 242
    .line 243
    .line 244
    move-result p1

    .line 245
    if-eqz p1, :cond_e

    .line 246
    .line 247
    div-int/2addr v5, v6

    .line 248
    invoke-static {v5, v4, v6}, Lkp/r9;->e(III)I

    .line 249
    .line 250
    .line 251
    move-result p1

    .line 252
    int-to-float p1, p1

    .line 253
    mul-float/2addr p1, v2

    .line 254
    add-float/2addr p1, p0

    .line 255
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    invoke-static {p0, v1}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    goto/16 :goto_2

    .line 267
    .line 268
    :cond_c
    if-ne v1, v4, :cond_e

    .line 269
    .line 270
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 271
    .line 272
    .line 273
    move-result p1

    .line 274
    invoke-static {p1}, Ljp/x1;->a(I)J

    .line 275
    .line 276
    .line 277
    move-result-wide v0

    .line 278
    sget-wide v5, Ln3/a;->d:J

    .line 279
    .line 280
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 281
    .line 282
    .line 283
    move-result p1

    .line 284
    if-nez p1, :cond_d

    .line 285
    .line 286
    sget-wide v5, Ln3/a;->e:J

    .line 287
    .line 288
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 289
    .line 290
    .line 291
    move-result p1

    .line 292
    if-nez p1, :cond_d

    .line 293
    .line 294
    sget-wide v5, Ln3/a;->g:J

    .line 295
    .line 296
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 297
    .line 298
    .line 299
    move-result p1

    .line 300
    if-nez p1, :cond_d

    .line 301
    .line 302
    sget-wide v5, Ln3/a;->f:J

    .line 303
    .line 304
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 305
    .line 306
    .line 307
    move-result p1

    .line 308
    if-nez p1, :cond_d

    .line 309
    .line 310
    sget-wide v5, Ln3/a;->m:J

    .line 311
    .line 312
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 313
    .line 314
    .line 315
    move-result p1

    .line 316
    if-nez p1, :cond_d

    .line 317
    .line 318
    sget-wide v5, Ln3/a;->n:J

    .line 319
    .line 320
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 321
    .line 322
    .line 323
    move-result p1

    .line 324
    if-nez p1, :cond_d

    .line 325
    .line 326
    sget-wide v5, Ln3/a;->o:J

    .line 327
    .line 328
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 329
    .line 330
    .line 331
    move-result p1

    .line 332
    if-nez p1, :cond_d

    .line 333
    .line 334
    sget-wide v5, Ln3/a;->p:J

    .line 335
    .line 336
    invoke-static {v0, v1, v5, v6}, Ln3/a;->a(JJ)Z

    .line 337
    .line 338
    .line 339
    move-result p1

    .line 340
    if-eqz p1, :cond_e

    .line 341
    .line 342
    :cond_d
    iget-object p0, p0, Lh2/o9;->j:Lay0/a;

    .line 343
    .line 344
    if-eqz p0, :cond_4

    .line 345
    .line 346
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    goto/16 :goto_2

    .line 350
    .line 351
    :cond_e
    :goto_3
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 352
    .line 353
    .line 354
    move-result-object p0

    .line 355
    return-object p0
.end method

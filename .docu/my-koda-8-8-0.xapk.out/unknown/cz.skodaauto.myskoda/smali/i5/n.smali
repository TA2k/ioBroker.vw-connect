.class public final Li5/n;
.super Li5/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public k:Li5/g;

.field public l:Li5/a;


# virtual methods
.method public final a(Li5/e;)V
    .locals 10

    .line 1
    iget p1, p0, Li5/p;->j:I

    .line 2
    .line 3
    invoke-static {p1}, Lu/w;->o(I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 v0, 0x3

    .line 8
    const/4 v1, 0x1

    .line 9
    if-eq p1, v0, :cond_e

    .line 10
    .line 11
    iget-object p1, p0, Li5/p;->e:Li5/h;

    .line 12
    .line 13
    iget-boolean v2, p1, Li5/g;->c:Z

    .line 14
    .line 15
    const/high16 v3, 0x3f000000    # 0.5f

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    if-eqz v2, :cond_5

    .line 19
    .line 20
    iget-boolean v2, p1, Li5/g;->j:Z

    .line 21
    .line 22
    if-nez v2, :cond_5

    .line 23
    .line 24
    iget v2, p0, Li5/p;->d:I

    .line 25
    .line 26
    if-ne v2, v0, :cond_5

    .line 27
    .line 28
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 29
    .line 30
    iget v5, v2, Lh5/d;->t:I

    .line 31
    .line 32
    const/4 v6, 0x2

    .line 33
    if-eq v5, v6, :cond_4

    .line 34
    .line 35
    if-eq v5, v0, :cond_0

    .line 36
    .line 37
    goto :goto_3

    .line 38
    :cond_0
    iget-object v5, v2, Lh5/d;->d:Li5/l;

    .line 39
    .line 40
    iget-object v5, v5, Li5/p;->e:Li5/h;

    .line 41
    .line 42
    iget-boolean v6, v5, Li5/g;->j:Z

    .line 43
    .line 44
    if-eqz v6, :cond_5

    .line 45
    .line 46
    iget v6, v2, Lh5/d;->Y:I

    .line 47
    .line 48
    const/4 v7, -0x1

    .line 49
    if-eq v6, v7, :cond_3

    .line 50
    .line 51
    if-eqz v6, :cond_2

    .line 52
    .line 53
    if-eq v6, v1, :cond_1

    .line 54
    .line 55
    move v2, v4

    .line 56
    goto :goto_2

    .line 57
    :cond_1
    iget v5, v5, Li5/g;->g:I

    .line 58
    .line 59
    int-to-float v5, v5

    .line 60
    iget v2, v2, Lh5/d;->X:F

    .line 61
    .line 62
    :goto_0
    div-float/2addr v5, v2

    .line 63
    :goto_1
    add-float/2addr v5, v3

    .line 64
    float-to-int v2, v5

    .line 65
    goto :goto_2

    .line 66
    :cond_2
    iget v5, v5, Li5/g;->g:I

    .line 67
    .line 68
    int-to-float v5, v5

    .line 69
    iget v2, v2, Lh5/d;->X:F

    .line 70
    .line 71
    mul-float/2addr v5, v2

    .line 72
    goto :goto_1

    .line 73
    :cond_3
    iget v5, v5, Li5/g;->g:I

    .line 74
    .line 75
    int-to-float v5, v5

    .line 76
    iget v2, v2, Lh5/d;->X:F

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :goto_2
    invoke-virtual {p1, v2}, Li5/h;->d(I)V

    .line 80
    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_4
    iget-object v5, v2, Lh5/d;->U:Lh5/e;

    .line 84
    .line 85
    if-eqz v5, :cond_5

    .line 86
    .line 87
    iget-object v5, v5, Lh5/d;->e:Li5/n;

    .line 88
    .line 89
    iget-object v5, v5, Li5/p;->e:Li5/h;

    .line 90
    .line 91
    iget-boolean v6, v5, Li5/g;->j:Z

    .line 92
    .line 93
    if-eqz v6, :cond_5

    .line 94
    .line 95
    iget v2, v2, Lh5/d;->A:F

    .line 96
    .line 97
    iget v5, v5, Li5/g;->g:I

    .line 98
    .line 99
    int-to-float v5, v5

    .line 100
    mul-float/2addr v5, v2

    .line 101
    add-float/2addr v5, v3

    .line 102
    float-to-int v2, v5

    .line 103
    invoke-virtual {p1, v2}, Li5/h;->d(I)V

    .line 104
    .line 105
    .line 106
    :cond_5
    :goto_3
    iget-object v2, p0, Li5/p;->h:Li5/g;

    .line 107
    .line 108
    iget-boolean v5, v2, Li5/g;->c:Z

    .line 109
    .line 110
    iget-object v6, v2, Li5/g;->l:Ljava/util/ArrayList;

    .line 111
    .line 112
    if-eqz v5, :cond_d

    .line 113
    .line 114
    iget-object v5, p0, Li5/p;->i:Li5/g;

    .line 115
    .line 116
    iget-boolean v7, v5, Li5/g;->c:Z

    .line 117
    .line 118
    iget-object v8, v5, Li5/g;->l:Ljava/util/ArrayList;

    .line 119
    .line 120
    if-nez v7, :cond_6

    .line 121
    .line 122
    goto/16 :goto_6

    .line 123
    .line 124
    :cond_6
    iget-boolean v7, v2, Li5/g;->j:Z

    .line 125
    .line 126
    if-eqz v7, :cond_7

    .line 127
    .line 128
    iget-boolean v7, v5, Li5/g;->j:Z

    .line 129
    .line 130
    if-eqz v7, :cond_7

    .line 131
    .line 132
    iget-boolean v7, p1, Li5/g;->j:Z

    .line 133
    .line 134
    if-eqz v7, :cond_7

    .line 135
    .line 136
    goto/16 :goto_6

    .line 137
    .line 138
    :cond_7
    iget-boolean v7, p1, Li5/g;->j:Z

    .line 139
    .line 140
    if-nez v7, :cond_8

    .line 141
    .line 142
    iget v7, p0, Li5/p;->d:I

    .line 143
    .line 144
    if-ne v7, v0, :cond_8

    .line 145
    .line 146
    iget-object v7, p0, Li5/p;->b:Lh5/d;

    .line 147
    .line 148
    iget v9, v7, Lh5/d;->s:I

    .line 149
    .line 150
    if-nez v9, :cond_8

    .line 151
    .line 152
    invoke-virtual {v7}, Lh5/d;->z()Z

    .line 153
    .line 154
    .line 155
    move-result v7

    .line 156
    if-nez v7, :cond_8

    .line 157
    .line 158
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    check-cast p0, Li5/g;

    .line 163
    .line 164
    invoke-virtual {v8, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    check-cast v0, Li5/g;

    .line 169
    .line 170
    iget p0, p0, Li5/g;->g:I

    .line 171
    .line 172
    iget v1, v2, Li5/g;->f:I

    .line 173
    .line 174
    add-int/2addr p0, v1

    .line 175
    iget v0, v0, Li5/g;->g:I

    .line 176
    .line 177
    iget v1, v5, Li5/g;->f:I

    .line 178
    .line 179
    add-int/2addr v0, v1

    .line 180
    sub-int v1, v0, p0

    .line 181
    .line 182
    invoke-virtual {v2, p0}, Li5/g;->d(I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v5, v0}, Li5/g;->d(I)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {p1, v1}, Li5/h;->d(I)V

    .line 189
    .line 190
    .line 191
    return-void

    .line 192
    :cond_8
    iget-boolean v7, p1, Li5/g;->j:Z

    .line 193
    .line 194
    if-nez v7, :cond_a

    .line 195
    .line 196
    iget v7, p0, Li5/p;->d:I

    .line 197
    .line 198
    if-ne v7, v0, :cond_a

    .line 199
    .line 200
    iget v0, p0, Li5/p;->a:I

    .line 201
    .line 202
    if-ne v0, v1, :cond_a

    .line 203
    .line 204
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 205
    .line 206
    .line 207
    move-result v0

    .line 208
    if-lez v0, :cond_a

    .line 209
    .line 210
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 211
    .line 212
    .line 213
    move-result v0

    .line 214
    if-lez v0, :cond_a

    .line 215
    .line 216
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    check-cast v0, Li5/g;

    .line 221
    .line 222
    invoke-virtual {v8, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v1

    .line 226
    check-cast v1, Li5/g;

    .line 227
    .line 228
    iget v0, v0, Li5/g;->g:I

    .line 229
    .line 230
    iget v7, v2, Li5/g;->f:I

    .line 231
    .line 232
    add-int/2addr v0, v7

    .line 233
    iget v1, v1, Li5/g;->g:I

    .line 234
    .line 235
    iget v7, v5, Li5/g;->f:I

    .line 236
    .line 237
    add-int/2addr v1, v7

    .line 238
    sub-int/2addr v1, v0

    .line 239
    iget v0, p1, Li5/h;->m:I

    .line 240
    .line 241
    if-ge v1, v0, :cond_9

    .line 242
    .line 243
    invoke-virtual {p1, v1}, Li5/h;->d(I)V

    .line 244
    .line 245
    .line 246
    goto :goto_4

    .line 247
    :cond_9
    invoke-virtual {p1, v0}, Li5/h;->d(I)V

    .line 248
    .line 249
    .line 250
    :cond_a
    :goto_4
    iget-boolean v0, p1, Li5/g;->j:Z

    .line 251
    .line 252
    if-nez v0, :cond_b

    .line 253
    .line 254
    goto :goto_6

    .line 255
    :cond_b
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 256
    .line 257
    .line 258
    move-result v0

    .line 259
    if-lez v0, :cond_d

    .line 260
    .line 261
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 262
    .line 263
    .line 264
    move-result v0

    .line 265
    if-lez v0, :cond_d

    .line 266
    .line 267
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    check-cast v0, Li5/g;

    .line 272
    .line 273
    invoke-virtual {v8, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    check-cast v1, Li5/g;

    .line 278
    .line 279
    iget v4, v0, Li5/g;->g:I

    .line 280
    .line 281
    iget v6, v2, Li5/g;->f:I

    .line 282
    .line 283
    add-int/2addr v6, v4

    .line 284
    iget v7, v1, Li5/g;->g:I

    .line 285
    .line 286
    iget v8, v5, Li5/g;->f:I

    .line 287
    .line 288
    add-int/2addr v8, v7

    .line 289
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 290
    .line 291
    iget p0, p0, Lh5/d;->f0:F

    .line 292
    .line 293
    if-ne v0, v1, :cond_c

    .line 294
    .line 295
    move p0, v3

    .line 296
    goto :goto_5

    .line 297
    :cond_c
    move v4, v6

    .line 298
    move v7, v8

    .line 299
    :goto_5
    sub-int/2addr v7, v4

    .line 300
    iget v0, p1, Li5/g;->g:I

    .line 301
    .line 302
    sub-int/2addr v7, v0

    .line 303
    int-to-float v0, v4

    .line 304
    add-float/2addr v0, v3

    .line 305
    int-to-float v1, v7

    .line 306
    mul-float/2addr v1, p0

    .line 307
    add-float/2addr v1, v0

    .line 308
    float-to-int p0, v1

    .line 309
    invoke-virtual {v2, p0}, Li5/g;->d(I)V

    .line 310
    .line 311
    .line 312
    iget p0, v2, Li5/g;->g:I

    .line 313
    .line 314
    iget p1, p1, Li5/g;->g:I

    .line 315
    .line 316
    add-int/2addr p0, p1

    .line 317
    invoke-virtual {v5, p0}, Li5/g;->d(I)V

    .line 318
    .line 319
    .line 320
    :cond_d
    :goto_6
    return-void

    .line 321
    :cond_e
    iget-object p1, p0, Li5/p;->b:Lh5/d;

    .line 322
    .line 323
    iget-object v0, p1, Lh5/d;->K:Lh5/c;

    .line 324
    .line 325
    iget-object p1, p1, Lh5/d;->M:Lh5/c;

    .line 326
    .line 327
    invoke-virtual {p0, v0, p1, v1}, Li5/p;->l(Lh5/c;Lh5/c;I)V

    .line 328
    .line 329
    .line 330
    return-void
.end method

.method public final d()V
    .locals 15

    .line 1
    iget-object v0, p0, Li5/n;->k:Li5/g;

    .line 2
    .line 3
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 4
    .line 5
    iget-boolean v2, v1, Lh5/d;->a:Z

    .line 6
    .line 7
    iget-object v3, p0, Li5/p;->e:Li5/h;

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-virtual {v3, v1}, Li5/h;->d(I)V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-boolean v1, v3, Li5/g;->j:Z

    .line 19
    .line 20
    iget-object v2, v3, Li5/g;->k:Ljava/util/ArrayList;

    .line 21
    .line 22
    iget-object v4, v3, Li5/g;->l:Ljava/util/ArrayList;

    .line 23
    .line 24
    const/4 v5, 0x4

    .line 25
    const/4 v6, 0x1

    .line 26
    const/4 v7, 0x3

    .line 27
    iget-object v8, p0, Li5/p;->i:Li5/g;

    .line 28
    .line 29
    iget-object v9, p0, Li5/p;->h:Li5/g;

    .line 30
    .line 31
    if-nez v1, :cond_3

    .line 32
    .line 33
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 34
    .line 35
    iget-object v10, v1, Lh5/d;->q0:[I

    .line 36
    .line 37
    aget v10, v10, v6

    .line 38
    .line 39
    iput v10, p0, Li5/p;->d:I

    .line 40
    .line 41
    iget-boolean v1, v1, Lh5/d;->F:Z

    .line 42
    .line 43
    if-eqz v1, :cond_1

    .line 44
    .line 45
    new-instance v1, Li5/a;

    .line 46
    .line 47
    invoke-direct {v1, p0}, Li5/h;-><init>(Li5/p;)V

    .line 48
    .line 49
    .line 50
    iput-object v1, p0, Li5/n;->l:Li5/a;

    .line 51
    .line 52
    :cond_1
    iget v1, p0, Li5/p;->d:I

    .line 53
    .line 54
    if-eq v1, v7, :cond_4

    .line 55
    .line 56
    if-ne v1, v5, :cond_2

    .line 57
    .line 58
    iget-object v10, p0, Li5/p;->b:Lh5/d;

    .line 59
    .line 60
    iget-object v10, v10, Lh5/d;->U:Lh5/e;

    .line 61
    .line 62
    if-eqz v10, :cond_2

    .line 63
    .line 64
    iget-object v11, v10, Lh5/d;->q0:[I

    .line 65
    .line 66
    aget v11, v11, v6

    .line 67
    .line 68
    if-ne v11, v6, :cond_2

    .line 69
    .line 70
    invoke-virtual {v10}, Lh5/d;->l()I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 75
    .line 76
    iget-object v1, v1, Lh5/d;->K:Lh5/c;

    .line 77
    .line 78
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    sub-int/2addr v0, v1

    .line 83
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 84
    .line 85
    iget-object v1, v1, Lh5/d;->M:Lh5/c;

    .line 86
    .line 87
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    sub-int/2addr v0, v1

    .line 92
    iget-object v1, v10, Lh5/d;->e:Li5/n;

    .line 93
    .line 94
    iget-object v1, v1, Li5/p;->h:Li5/g;

    .line 95
    .line 96
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 97
    .line 98
    iget-object v2, v2, Lh5/d;->K:Lh5/c;

    .line 99
    .line 100
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    invoke-static {v9, v1, v2}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 105
    .line 106
    .line 107
    iget-object v1, v10, Lh5/d;->e:Li5/n;

    .line 108
    .line 109
    iget-object v1, v1, Li5/p;->i:Li5/g;

    .line 110
    .line 111
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 112
    .line 113
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 114
    .line 115
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    neg-int p0, p0

    .line 120
    invoke-static {v8, v1, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v3, v0}, Li5/h;->d(I)V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :cond_2
    if-ne v1, v6, :cond_4

    .line 128
    .line 129
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 130
    .line 131
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    invoke-virtual {v3, v1}, Li5/h;->d(I)V

    .line 136
    .line 137
    .line 138
    goto :goto_0

    .line 139
    :cond_3
    iget v1, p0, Li5/p;->d:I

    .line 140
    .line 141
    if-ne v1, v5, :cond_4

    .line 142
    .line 143
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 144
    .line 145
    iget-object v10, v1, Lh5/d;->U:Lh5/e;

    .line 146
    .line 147
    if-eqz v10, :cond_4

    .line 148
    .line 149
    iget-object v11, v10, Lh5/d;->q0:[I

    .line 150
    .line 151
    aget v11, v11, v6

    .line 152
    .line 153
    if-ne v11, v6, :cond_4

    .line 154
    .line 155
    iget-object v0, v10, Lh5/d;->e:Li5/n;

    .line 156
    .line 157
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 158
    .line 159
    iget-object v1, v1, Lh5/d;->K:Lh5/c;

    .line 160
    .line 161
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    invoke-static {v9, v0, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 166
    .line 167
    .line 168
    iget-object v0, v10, Lh5/d;->e:Li5/n;

    .line 169
    .line 170
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 171
    .line 172
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 173
    .line 174
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 175
    .line 176
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 177
    .line 178
    .line 179
    move-result p0

    .line 180
    neg-int p0, p0

    .line 181
    invoke-static {v8, v0, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 182
    .line 183
    .line 184
    return-void

    .line 185
    :cond_4
    :goto_0
    iget-boolean v1, v3, Li5/g;->j:Z

    .line 186
    .line 187
    const/4 v10, 0x0

    .line 188
    const/4 v11, 0x2

    .line 189
    if-eqz v1, :cond_d

    .line 190
    .line 191
    iget-object v12, p0, Li5/p;->b:Lh5/d;

    .line 192
    .line 193
    iget-boolean v13, v12, Lh5/d;->a:Z

    .line 194
    .line 195
    if-eqz v13, :cond_d

    .line 196
    .line 197
    iget-object v1, v12, Lh5/d;->R:[Lh5/c;

    .line 198
    .line 199
    aget-object v2, v1, v11

    .line 200
    .line 201
    iget-object v4, v2, Lh5/c;->f:Lh5/c;

    .line 202
    .line 203
    if-eqz v4, :cond_8

    .line 204
    .line 205
    aget-object v13, v1, v7

    .line 206
    .line 207
    iget-object v13, v13, Lh5/c;->f:Lh5/c;

    .line 208
    .line 209
    if-eqz v13, :cond_8

    .line 210
    .line 211
    invoke-virtual {v12}, Lh5/d;->z()Z

    .line 212
    .line 213
    .line 214
    move-result v1

    .line 215
    if-eqz v1, :cond_5

    .line 216
    .line 217
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 218
    .line 219
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 220
    .line 221
    aget-object v1, v1, v11

    .line 222
    .line 223
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 224
    .line 225
    .line 226
    move-result v1

    .line 227
    iput v1, v9, Li5/g;->f:I

    .line 228
    .line 229
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 230
    .line 231
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 232
    .line 233
    aget-object v1, v1, v7

    .line 234
    .line 235
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 236
    .line 237
    .line 238
    move-result v1

    .line 239
    neg-int v1, v1

    .line 240
    iput v1, v8, Li5/g;->f:I

    .line 241
    .line 242
    goto :goto_1

    .line 243
    :cond_5
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 244
    .line 245
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 246
    .line 247
    aget-object v1, v1, v11

    .line 248
    .line 249
    invoke-static {v1}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    if-eqz v1, :cond_6

    .line 254
    .line 255
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 256
    .line 257
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 258
    .line 259
    aget-object v2, v2, v11

    .line 260
    .line 261
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 262
    .line 263
    .line 264
    move-result v2

    .line 265
    invoke-static {v9, v1, v2}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 266
    .line 267
    .line 268
    :cond_6
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 269
    .line 270
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 271
    .line 272
    aget-object v1, v1, v7

    .line 273
    .line 274
    invoke-static {v1}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    if-eqz v1, :cond_7

    .line 279
    .line 280
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 281
    .line 282
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 283
    .line 284
    aget-object v2, v2, v7

    .line 285
    .line 286
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 287
    .line 288
    .line 289
    move-result v2

    .line 290
    neg-int v2, v2

    .line 291
    invoke-static {v8, v1, v2}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 292
    .line 293
    .line 294
    :cond_7
    iput-boolean v6, v9, Li5/g;->b:Z

    .line 295
    .line 296
    iput-boolean v6, v8, Li5/g;->b:Z

    .line 297
    .line 298
    :goto_1
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 299
    .line 300
    iget-boolean v1, p0, Lh5/d;->F:Z

    .line 301
    .line 302
    if-eqz v1, :cond_1e

    .line 303
    .line 304
    iget p0, p0, Lh5/d;->b0:I

    .line 305
    .line 306
    invoke-static {v0, v9, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 307
    .line 308
    .line 309
    return-void

    .line 310
    :cond_8
    if-eqz v4, :cond_9

    .line 311
    .line 312
    invoke-static {v2}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    if-eqz v1, :cond_1e

    .line 317
    .line 318
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 319
    .line 320
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 321
    .line 322
    aget-object v2, v2, v11

    .line 323
    .line 324
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 325
    .line 326
    .line 327
    move-result v2

    .line 328
    invoke-static {v9, v1, v2}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 329
    .line 330
    .line 331
    iget v1, v3, Li5/g;->g:I

    .line 332
    .line 333
    invoke-static {v8, v9, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 334
    .line 335
    .line 336
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 337
    .line 338
    iget-boolean v1, p0, Lh5/d;->F:Z

    .line 339
    .line 340
    if-eqz v1, :cond_1e

    .line 341
    .line 342
    iget p0, p0, Lh5/d;->b0:I

    .line 343
    .line 344
    invoke-static {v0, v9, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 345
    .line 346
    .line 347
    return-void

    .line 348
    :cond_9
    aget-object v2, v1, v7

    .line 349
    .line 350
    iget-object v4, v2, Lh5/c;->f:Lh5/c;

    .line 351
    .line 352
    if-eqz v4, :cond_b

    .line 353
    .line 354
    invoke-static {v2}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 355
    .line 356
    .line 357
    move-result-object v1

    .line 358
    if-eqz v1, :cond_a

    .line 359
    .line 360
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 361
    .line 362
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 363
    .line 364
    aget-object v2, v2, v7

    .line 365
    .line 366
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 367
    .line 368
    .line 369
    move-result v2

    .line 370
    neg-int v2, v2

    .line 371
    invoke-static {v8, v1, v2}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 372
    .line 373
    .line 374
    iget v1, v3, Li5/g;->g:I

    .line 375
    .line 376
    neg-int v1, v1

    .line 377
    invoke-static {v9, v8, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 378
    .line 379
    .line 380
    :cond_a
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 381
    .line 382
    iget-boolean v1, p0, Lh5/d;->F:Z

    .line 383
    .line 384
    if-eqz v1, :cond_1e

    .line 385
    .line 386
    iget p0, p0, Lh5/d;->b0:I

    .line 387
    .line 388
    invoke-static {v0, v9, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 389
    .line 390
    .line 391
    return-void

    .line 392
    :cond_b
    aget-object v1, v1, v5

    .line 393
    .line 394
    iget-object v2, v1, Lh5/c;->f:Lh5/c;

    .line 395
    .line 396
    if-eqz v2, :cond_c

    .line 397
    .line 398
    invoke-static {v1}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    if-eqz v1, :cond_1e

    .line 403
    .line 404
    invoke-static {v0, v1, v10}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 405
    .line 406
    .line 407
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 408
    .line 409
    iget p0, p0, Lh5/d;->b0:I

    .line 410
    .line 411
    neg-int p0, p0

    .line 412
    invoke-static {v9, v0, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 413
    .line 414
    .line 415
    iget p0, v3, Li5/g;->g:I

    .line 416
    .line 417
    invoke-static {v8, v9, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 418
    .line 419
    .line 420
    return-void

    .line 421
    :cond_c
    instance-of v1, v12, Lh5/i;

    .line 422
    .line 423
    if-nez v1, :cond_1e

    .line 424
    .line 425
    iget-object v1, v12, Lh5/d;->U:Lh5/e;

    .line 426
    .line 427
    if-eqz v1, :cond_1e

    .line 428
    .line 429
    const/4 v1, 0x7

    .line 430
    invoke-virtual {v12, v1}, Lh5/d;->j(I)Lh5/c;

    .line 431
    .line 432
    .line 433
    move-result-object v1

    .line 434
    iget-object v1, v1, Lh5/c;->f:Lh5/c;

    .line 435
    .line 436
    if-nez v1, :cond_1e

    .line 437
    .line 438
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 439
    .line 440
    iget-object v2, v1, Lh5/d;->U:Lh5/e;

    .line 441
    .line 442
    iget-object v2, v2, Lh5/d;->e:Li5/n;

    .line 443
    .line 444
    iget-object v2, v2, Li5/p;->h:Li5/g;

    .line 445
    .line 446
    invoke-virtual {v1}, Lh5/d;->t()I

    .line 447
    .line 448
    .line 449
    move-result v1

    .line 450
    invoke-static {v9, v2, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 451
    .line 452
    .line 453
    iget v1, v3, Li5/g;->g:I

    .line 454
    .line 455
    invoke-static {v8, v9, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 456
    .line 457
    .line 458
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 459
    .line 460
    iget-boolean v1, p0, Lh5/d;->F:Z

    .line 461
    .line 462
    if-eqz v1, :cond_1e

    .line 463
    .line 464
    iget p0, p0, Lh5/d;->b0:I

    .line 465
    .line 466
    invoke-static {v0, v9, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 467
    .line 468
    .line 469
    return-void

    .line 470
    :cond_d
    if-nez v1, :cond_12

    .line 471
    .line 472
    iget v1, p0, Li5/p;->d:I

    .line 473
    .line 474
    if-ne v1, v7, :cond_12

    .line 475
    .line 476
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 477
    .line 478
    iget v12, v1, Lh5/d;->t:I

    .line 479
    .line 480
    if-eq v12, v11, :cond_10

    .line 481
    .line 482
    if-eq v12, v7, :cond_e

    .line 483
    .line 484
    goto :goto_2

    .line 485
    :cond_e
    invoke-virtual {v1}, Lh5/d;->z()Z

    .line 486
    .line 487
    .line 488
    move-result v1

    .line 489
    if-nez v1, :cond_13

    .line 490
    .line 491
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 492
    .line 493
    iget v12, v1, Lh5/d;->s:I

    .line 494
    .line 495
    if-ne v12, v7, :cond_f

    .line 496
    .line 497
    goto :goto_2

    .line 498
    :cond_f
    iget-object v1, v1, Lh5/d;->d:Li5/l;

    .line 499
    .line 500
    iget-object v1, v1, Li5/p;->e:Li5/h;

    .line 501
    .line 502
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 503
    .line 504
    .line 505
    iget-object v1, v1, Li5/g;->k:Ljava/util/ArrayList;

    .line 506
    .line 507
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 508
    .line 509
    .line 510
    iput-boolean v6, v3, Li5/g;->b:Z

    .line 511
    .line 512
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 513
    .line 514
    .line 515
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 516
    .line 517
    .line 518
    goto :goto_2

    .line 519
    :cond_10
    iget-object v1, v1, Lh5/d;->U:Lh5/e;

    .line 520
    .line 521
    if-nez v1, :cond_11

    .line 522
    .line 523
    goto :goto_2

    .line 524
    :cond_11
    iget-object v1, v1, Lh5/d;->e:Li5/n;

    .line 525
    .line 526
    iget-object v1, v1, Li5/p;->e:Li5/h;

    .line 527
    .line 528
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 529
    .line 530
    .line 531
    iget-object v1, v1, Li5/g;->k:Ljava/util/ArrayList;

    .line 532
    .line 533
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    iput-boolean v6, v3, Li5/g;->b:Z

    .line 537
    .line 538
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 539
    .line 540
    .line 541
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 542
    .line 543
    .line 544
    goto :goto_2

    .line 545
    :cond_12
    invoke-virtual {v3, p0}, Li5/g;->b(Li5/p;)V

    .line 546
    .line 547
    .line 548
    :cond_13
    :goto_2
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 549
    .line 550
    iget-object v2, v1, Lh5/d;->R:[Lh5/c;

    .line 551
    .line 552
    aget-object v12, v2, v11

    .line 553
    .line 554
    iget-object v13, v12, Lh5/c;->f:Lh5/c;

    .line 555
    .line 556
    if-eqz v13, :cond_17

    .line 557
    .line 558
    aget-object v14, v2, v7

    .line 559
    .line 560
    iget-object v14, v14, Lh5/c;->f:Lh5/c;

    .line 561
    .line 562
    if-eqz v14, :cond_17

    .line 563
    .line 564
    invoke-virtual {v1}, Lh5/d;->z()Z

    .line 565
    .line 566
    .line 567
    move-result v1

    .line 568
    if-eqz v1, :cond_14

    .line 569
    .line 570
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 571
    .line 572
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 573
    .line 574
    aget-object v1, v1, v11

    .line 575
    .line 576
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 577
    .line 578
    .line 579
    move-result v1

    .line 580
    iput v1, v9, Li5/g;->f:I

    .line 581
    .line 582
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 583
    .line 584
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 585
    .line 586
    aget-object v1, v1, v7

    .line 587
    .line 588
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 589
    .line 590
    .line 591
    move-result v1

    .line 592
    neg-int v1, v1

    .line 593
    iput v1, v8, Li5/g;->f:I

    .line 594
    .line 595
    goto :goto_3

    .line 596
    :cond_14
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 597
    .line 598
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 599
    .line 600
    aget-object v1, v1, v11

    .line 601
    .line 602
    invoke-static {v1}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 603
    .line 604
    .line 605
    move-result-object v1

    .line 606
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 607
    .line 608
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 609
    .line 610
    aget-object v2, v2, v7

    .line 611
    .line 612
    invoke-static {v2}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 613
    .line 614
    .line 615
    move-result-object v2

    .line 616
    if-eqz v1, :cond_15

    .line 617
    .line 618
    invoke-virtual {v1, p0}, Li5/g;->b(Li5/p;)V

    .line 619
    .line 620
    .line 621
    :cond_15
    if-eqz v2, :cond_16

    .line 622
    .line 623
    invoke-virtual {v2, p0}, Li5/g;->b(Li5/p;)V

    .line 624
    .line 625
    .line 626
    :cond_16
    iput v5, p0, Li5/p;->j:I

    .line 627
    .line 628
    :goto_3
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 629
    .line 630
    iget-boolean v1, v1, Lh5/d;->F:Z

    .line 631
    .line 632
    if-eqz v1, :cond_1d

    .line 633
    .line 634
    iget-object v1, p0, Li5/n;->l:Li5/a;

    .line 635
    .line 636
    invoke-virtual {p0, v0, v9, v6, v1}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 637
    .line 638
    .line 639
    goto/16 :goto_4

    .line 640
    .line 641
    :cond_17
    const/4 v14, 0x0

    .line 642
    if-eqz v13, :cond_19

    .line 643
    .line 644
    invoke-static {v12}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 645
    .line 646
    .line 647
    move-result-object v1

    .line 648
    if-eqz v1, :cond_1d

    .line 649
    .line 650
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 651
    .line 652
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 653
    .line 654
    aget-object v2, v2, v11

    .line 655
    .line 656
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 657
    .line 658
    .line 659
    move-result v2

    .line 660
    invoke-static {v9, v1, v2}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 661
    .line 662
    .line 663
    invoke-virtual {p0, v8, v9, v6, v3}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 664
    .line 665
    .line 666
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 667
    .line 668
    iget-boolean v1, v1, Lh5/d;->F:Z

    .line 669
    .line 670
    if-eqz v1, :cond_18

    .line 671
    .line 672
    iget-object v1, p0, Li5/n;->l:Li5/a;

    .line 673
    .line 674
    invoke-virtual {p0, v0, v9, v6, v1}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 675
    .line 676
    .line 677
    :cond_18
    iget v0, p0, Li5/p;->d:I

    .line 678
    .line 679
    if-ne v0, v7, :cond_1d

    .line 680
    .line 681
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 682
    .line 683
    iget v1, v0, Lh5/d;->X:F

    .line 684
    .line 685
    cmpl-float v1, v1, v14

    .line 686
    .line 687
    if-lez v1, :cond_1d

    .line 688
    .line 689
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 690
    .line 691
    iget v1, v0, Li5/p;->d:I

    .line 692
    .line 693
    if-ne v1, v7, :cond_1d

    .line 694
    .line 695
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 696
    .line 697
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 698
    .line 699
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 700
    .line 701
    .line 702
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 703
    .line 704
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 705
    .line 706
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 707
    .line 708
    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 709
    .line 710
    .line 711
    iput-object p0, v3, Li5/g;->a:Li5/p;

    .line 712
    .line 713
    goto/16 :goto_4

    .line 714
    .line 715
    :cond_19
    aget-object v11, v2, v7

    .line 716
    .line 717
    iget-object v12, v11, Lh5/c;->f:Lh5/c;

    .line 718
    .line 719
    const/4 v13, -0x1

    .line 720
    if-eqz v12, :cond_1a

    .line 721
    .line 722
    invoke-static {v11}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 723
    .line 724
    .line 725
    move-result-object v1

    .line 726
    if-eqz v1, :cond_1d

    .line 727
    .line 728
    iget-object v2, p0, Li5/p;->b:Lh5/d;

    .line 729
    .line 730
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 731
    .line 732
    aget-object v2, v2, v7

    .line 733
    .line 734
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 735
    .line 736
    .line 737
    move-result v2

    .line 738
    neg-int v2, v2

    .line 739
    invoke-static {v8, v1, v2}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 740
    .line 741
    .line 742
    invoke-virtual {p0, v9, v8, v13, v3}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 743
    .line 744
    .line 745
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 746
    .line 747
    iget-boolean v1, v1, Lh5/d;->F:Z

    .line 748
    .line 749
    if-eqz v1, :cond_1d

    .line 750
    .line 751
    iget-object v1, p0, Li5/n;->l:Li5/a;

    .line 752
    .line 753
    invoke-virtual {p0, v0, v9, v6, v1}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 754
    .line 755
    .line 756
    goto :goto_4

    .line 757
    :cond_1a
    aget-object v2, v2, v5

    .line 758
    .line 759
    iget-object v5, v2, Lh5/c;->f:Lh5/c;

    .line 760
    .line 761
    if-eqz v5, :cond_1b

    .line 762
    .line 763
    invoke-static {v2}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 764
    .line 765
    .line 766
    move-result-object v1

    .line 767
    if-eqz v1, :cond_1d

    .line 768
    .line 769
    invoke-static {v0, v1, v10}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 770
    .line 771
    .line 772
    iget-object v1, p0, Li5/n;->l:Li5/a;

    .line 773
    .line 774
    invoke-virtual {p0, v9, v0, v13, v1}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 775
    .line 776
    .line 777
    invoke-virtual {p0, v8, v9, v6, v3}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 778
    .line 779
    .line 780
    goto :goto_4

    .line 781
    :cond_1b
    instance-of v2, v1, Lh5/i;

    .line 782
    .line 783
    if-nez v2, :cond_1d

    .line 784
    .line 785
    iget-object v2, v1, Lh5/d;->U:Lh5/e;

    .line 786
    .line 787
    if-eqz v2, :cond_1d

    .line 788
    .line 789
    iget-object v2, v2, Lh5/d;->e:Li5/n;

    .line 790
    .line 791
    iget-object v2, v2, Li5/p;->h:Li5/g;

    .line 792
    .line 793
    invoke-virtual {v1}, Lh5/d;->t()I

    .line 794
    .line 795
    .line 796
    move-result v1

    .line 797
    invoke-static {v9, v2, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 798
    .line 799
    .line 800
    invoke-virtual {p0, v8, v9, v6, v3}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 801
    .line 802
    .line 803
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 804
    .line 805
    iget-boolean v1, v1, Lh5/d;->F:Z

    .line 806
    .line 807
    if-eqz v1, :cond_1c

    .line 808
    .line 809
    iget-object v1, p0, Li5/n;->l:Li5/a;

    .line 810
    .line 811
    invoke-virtual {p0, v0, v9, v6, v1}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 812
    .line 813
    .line 814
    :cond_1c
    iget v0, p0, Li5/p;->d:I

    .line 815
    .line 816
    if-ne v0, v7, :cond_1d

    .line 817
    .line 818
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 819
    .line 820
    iget v1, v0, Lh5/d;->X:F

    .line 821
    .line 822
    cmpl-float v1, v1, v14

    .line 823
    .line 824
    if-lez v1, :cond_1d

    .line 825
    .line 826
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 827
    .line 828
    iget v1, v0, Li5/p;->d:I

    .line 829
    .line 830
    if-ne v1, v7, :cond_1d

    .line 831
    .line 832
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 833
    .line 834
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 835
    .line 836
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 837
    .line 838
    .line 839
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 840
    .line 841
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 842
    .line 843
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 844
    .line 845
    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 846
    .line 847
    .line 848
    iput-object p0, v3, Li5/g;->a:Li5/p;

    .line 849
    .line 850
    :cond_1d
    :goto_4
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 851
    .line 852
    .line 853
    move-result p0

    .line 854
    if-nez p0, :cond_1e

    .line 855
    .line 856
    iput-boolean v6, v3, Li5/g;->c:Z

    .line 857
    .line 858
    :cond_1e
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object v0, p0, Li5/p;->h:Li5/g;

    .line 2
    .line 3
    iget-boolean v1, v0, Li5/g;->j:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 8
    .line 9
    iget v0, v0, Li5/g;->g:I

    .line 10
    .line 11
    iput v0, p0, Lh5/d;->a0:I

    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final f()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Li5/p;->c:Li5/m;

    .line 3
    .line 4
    iget-object v0, p0, Li5/p;->h:Li5/g;

    .line 5
    .line 6
    invoke-virtual {v0}, Li5/g;->c()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Li5/p;->i:Li5/g;

    .line 10
    .line 11
    invoke-virtual {v0}, Li5/g;->c()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Li5/n;->k:Li5/g;

    .line 15
    .line 16
    invoke-virtual {v0}, Li5/g;->c()V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Li5/p;->e:Li5/h;

    .line 20
    .line 21
    invoke-virtual {v0}, Li5/g;->c()V

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    iput-boolean v0, p0, Li5/p;->g:Z

    .line 26
    .line 27
    return-void
.end method

.method public final k()Z
    .locals 2

    .line 1
    iget v0, p0, Li5/p;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 7
    .line 8
    iget p0, p0, Lh5/d;->t:I

    .line 9
    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0

    .line 15
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 16
    return p0
.end method

.method public final m()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Li5/p;->g:Z

    .line 3
    .line 4
    iget-object v1, p0, Li5/p;->h:Li5/g;

    .line 5
    .line 6
    invoke-virtual {v1}, Li5/g;->c()V

    .line 7
    .line 8
    .line 9
    iput-boolean v0, v1, Li5/g;->j:Z

    .line 10
    .line 11
    iget-object v1, p0, Li5/p;->i:Li5/g;

    .line 12
    .line 13
    invoke-virtual {v1}, Li5/g;->c()V

    .line 14
    .line 15
    .line 16
    iput-boolean v0, v1, Li5/g;->j:Z

    .line 17
    .line 18
    iget-object v1, p0, Li5/n;->k:Li5/g;

    .line 19
    .line 20
    invoke-virtual {v1}, Li5/g;->c()V

    .line 21
    .line 22
    .line 23
    iput-boolean v0, v1, Li5/g;->j:Z

    .line 24
    .line 25
    iget-object p0, p0, Li5/p;->e:Li5/h;

    .line 26
    .line 27
    iput-boolean v0, p0, Li5/g;->j:Z

    .line 28
    .line 29
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "VerticalRun "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 9
    .line 10
    iget-object p0, p0, Lh5/d;->i0:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

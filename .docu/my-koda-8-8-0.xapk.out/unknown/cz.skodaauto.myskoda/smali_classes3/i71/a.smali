.class public abstract Li71/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh71/l;


# direct methods
.method static constructor <clinit>()V
    .locals 36

    .line 1
    const-wide v0, 0xff000000L

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 7
    .line 8
    .line 9
    move-result-wide v3

    .line 10
    const-wide v0, 0xff161718L

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    const-wide v5, 0xffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    invoke-static {v5, v6}, Le3/j0;->e(J)J

    .line 25
    .line 26
    .line 27
    move-result-wide v14

    .line 28
    const-wide v5, 0xffc2cacfL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    invoke-static {v5, v6}, Le3/j0;->e(J)J

    .line 34
    .line 35
    .line 36
    move-result-wide v10

    .line 37
    const-wide v5, 0xff78faaeL

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    invoke-static {v5, v6}, Le3/j0;->e(J)J

    .line 43
    .line 44
    .line 45
    move-result-wide v8

    .line 46
    const-wide v5, 0xff128836L

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    invoke-static {v5, v6}, Le3/j0;->e(J)J

    .line 52
    .line 53
    .line 54
    move-result-wide v5

    .line 55
    const-wide v12, 0xffe4002cL

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    invoke-static {v12, v13}, Le3/j0;->e(J)J

    .line 61
    .line 62
    .line 63
    move-result-wide v12

    .line 64
    new-instance v7, Lh71/x;

    .line 65
    .line 66
    move-wide/from16 v16, v12

    .line 67
    .line 68
    const/4 v12, 0x0

    .line 69
    move-wide/from16 v18, v14

    .line 70
    .line 71
    move-wide/from16 v14, v16

    .line 72
    .line 73
    invoke-direct/range {v7 .. v12}, Lh71/x;-><init>(JJLe3/s;)V

    .line 74
    .line 75
    .line 76
    move-object v2, v7

    .line 77
    new-instance v7, Lh71/w;

    .line 78
    .line 79
    sget-object v12, Lh71/c;->d:Lh71/c;

    .line 80
    .line 81
    move-object v13, v7

    .line 82
    new-instance v7, Lh71/d;

    .line 83
    .line 84
    const v14, 0x3f266666    # 0.65f

    .line 85
    .line 86
    .line 87
    move-wide/from16 v20, v10

    .line 88
    .line 89
    invoke-static {v8, v9, v14}, Le3/s;->b(JF)J

    .line 90
    .line 91
    .line 92
    move-result-wide v10

    .line 93
    move-object/from16 v28, v12

    .line 94
    .line 95
    move-object v15, v13

    .line 96
    move-wide/from16 v12, v20

    .line 97
    .line 98
    invoke-direct/range {v7 .. v13}, Lh71/d;-><init>(JJJ)V

    .line 99
    .line 100
    .line 101
    move-wide/from16 v22, v8

    .line 102
    .line 103
    move-wide v10, v12

    .line 104
    move-object v9, v7

    .line 105
    move-object v7, v2

    .line 106
    new-instance v2, Lh71/d;

    .line 107
    .line 108
    move-wide v12, v5

    .line 109
    invoke-static {v3, v4, v14}, Le3/s;->b(JF)J

    .line 110
    .line 111
    .line 112
    move-result-wide v5

    .line 113
    move-object/from16 v20, v7

    .line 114
    .line 115
    invoke-static {v3, v4, v14}, Le3/s;->b(JF)J

    .line 116
    .line 117
    .line 118
    move-result-wide v7

    .line 119
    move-object/from16 v14, v20

    .line 120
    .line 121
    invoke-direct/range {v2 .. v8}, Lh71/d;-><init>(JJJ)V

    .line 122
    .line 123
    .line 124
    move-object v5, v2

    .line 125
    move-object/from16 v2, v28

    .line 126
    .line 127
    invoke-direct {v15, v2, v9, v5, v14}, Lh71/w;-><init>(Lh71/c;Lh71/d;Lh71/d;Lh71/x;)V

    .line 128
    .line 129
    .line 130
    sget-object v5, Lh71/c;->e:Lh71/c;

    .line 131
    .line 132
    new-instance v6, Lh71/w;

    .line 133
    .line 134
    invoke-direct {v6, v5, v9, v9, v14}, Lh71/w;-><init>(Lh71/c;Lh71/d;Lh71/d;Lh71/x;)V

    .line 135
    .line 136
    .line 137
    new-instance v28, Lh71/l;

    .line 138
    .line 139
    new-instance v5, Lh71/e;

    .line 140
    .line 141
    invoke-direct {v5, v3, v4, v3, v4}, Lh71/e;-><init>(JJ)V

    .line 142
    .line 143
    .line 144
    new-instance v26, Lh71/j;

    .line 145
    .line 146
    const v7, 0x3ee66666    # 0.45f

    .line 147
    .line 148
    .line 149
    invoke-static {v0, v1, v7}, Le3/s;->b(JF)J

    .line 150
    .line 151
    .line 152
    move-result-wide v7

    .line 153
    move-wide/from16 v24, v10

    .line 154
    .line 155
    move-wide v10, v7

    .line 156
    move-wide v8, v0

    .line 157
    move-wide/from16 v29, v12

    .line 158
    .line 159
    move-wide v12, v0

    .line 160
    move-object/from16 v21, v6

    .line 161
    .line 162
    move-wide/from16 v32, v29

    .line 163
    .line 164
    move-wide v6, v0

    .line 165
    move-object/from16 v29, v5

    .line 166
    .line 167
    move-wide/from16 v0, v24

    .line 168
    .line 169
    move-object/from16 v5, v26

    .line 170
    .line 171
    invoke-direct/range {v5 .. v13}, Lh71/j;-><init>(JJJJ)V

    .line 172
    .line 173
    .line 174
    move-object/from16 v30, v5

    .line 175
    .line 176
    new-instance v27, Lh71/f;

    .line 177
    .line 178
    new-instance v25, Lh71/w;

    .line 179
    .line 180
    move-object v5, v2

    .line 181
    new-instance v2, Lh71/d;

    .line 182
    .line 183
    move-object v7, v5

    .line 184
    move-wide v5, v3

    .line 185
    move-object v9, v7

    .line 186
    move-wide v7, v3

    .line 187
    invoke-direct/range {v2 .. v8}, Lh71/d;-><init>(JJJ)V

    .line 188
    .line 189
    .line 190
    new-instance v7, Lh71/d;

    .line 191
    .line 192
    move-wide/from16 v10, v18

    .line 193
    .line 194
    move-wide/from16 v12, v18

    .line 195
    .line 196
    move-object v5, v9

    .line 197
    move-wide/from16 v8, v18

    .line 198
    .line 199
    move-object/from16 v6, v25

    .line 200
    .line 201
    invoke-direct/range {v7 .. v13}, Lh71/d;-><init>(JJJ)V

    .line 202
    .line 203
    .line 204
    move-object v13, v7

    .line 205
    new-instance v12, Le3/s;

    .line 206
    .line 207
    invoke-direct {v12, v0, v1}, Le3/s;-><init>(J)V

    .line 208
    .line 209
    .line 210
    new-instance v7, Lh71/x;

    .line 211
    .line 212
    move-wide v10, v0

    .line 213
    move-wide v0, v8

    .line 214
    move-wide/from16 v8, v22

    .line 215
    .line 216
    invoke-direct/range {v7 .. v12}, Lh71/x;-><init>(JJLe3/s;)V

    .line 217
    .line 218
    .line 219
    invoke-direct {v6, v5, v2, v13, v7}, Lh71/w;-><init>(Lh71/c;Lh71/d;Lh71/d;Lh71/x;)V

    .line 220
    .line 221
    .line 222
    new-instance v2, Lh71/b;

    .line 223
    .line 224
    new-instance v7, Lh71/d;

    .line 225
    .line 226
    move-wide v12, v10

    .line 227
    move-wide/from16 v8, v16

    .line 228
    .line 229
    const v5, 0x3f266666    # 0.65f

    .line 230
    .line 231
    .line 232
    invoke-static {v8, v9, v5}, Le3/s;->b(JF)J

    .line 233
    .line 234
    .line 235
    move-result-wide v10

    .line 236
    invoke-direct/range {v7 .. v13}, Lh71/d;-><init>(JJJ)V

    .line 237
    .line 238
    .line 239
    move-wide/from16 v34, v12

    .line 240
    .line 241
    new-instance v8, Lh71/d;

    .line 242
    .line 243
    invoke-static {v0, v1, v5}, Le3/s;->b(JF)J

    .line 244
    .line 245
    .line 246
    move-result-wide v10

    .line 247
    invoke-static {v0, v1, v5}, Le3/s;->b(JF)J

    .line 248
    .line 249
    .line 250
    move-result-wide v12

    .line 251
    move-object v5, v7

    .line 252
    move-object v7, v8

    .line 253
    move-wide v8, v0

    .line 254
    move-wide/from16 v0, v16

    .line 255
    .line 256
    invoke-direct/range {v7 .. v13}, Lh71/d;-><init>(JJJ)V

    .line 257
    .line 258
    .line 259
    invoke-direct {v2, v5, v7}, Lh71/b;-><init>(Lh71/d;Lh71/d;)V

    .line 260
    .line 261
    .line 262
    move-object/from16 v26, v2

    .line 263
    .line 264
    new-instance v2, Lh71/v;

    .line 265
    .line 266
    move-wide/from16 v18, v8

    .line 267
    .line 268
    move-wide/from16 v7, v18

    .line 269
    .line 270
    move-wide v5, v3

    .line 271
    move-wide/from16 v3, v18

    .line 272
    .line 273
    invoke-direct/range {v2 .. v8}, Lh71/v;-><init>(JJJ)V

    .line 274
    .line 275
    .line 276
    move-wide v8, v3

    .line 277
    move-object/from16 v20, v15

    .line 278
    .line 279
    move-wide/from16 v17, v22

    .line 280
    .line 281
    move-object/from16 v22, v21

    .line 282
    .line 283
    move-object/from16 v23, v15

    .line 284
    .line 285
    move-object/from16 v24, v21

    .line 286
    .line 287
    move-object/from16 v19, v15

    .line 288
    .line 289
    move-object/from16 v16, v27

    .line 290
    .line 291
    move-object/from16 v27, v2

    .line 292
    .line 293
    invoke-direct/range {v16 .. v27}, Lh71/f;-><init>(JLh71/w;Lh71/w;Lh71/w;Lh71/w;Lh71/w;Lh71/w;Lh71/w;Lh71/b;Lh71/v;)V

    .line 294
    .line 295
    .line 296
    move-object/from16 v27, v16

    .line 297
    .line 298
    move-wide/from16 v22, v17

    .line 299
    .line 300
    new-instance v2, Lh71/h;

    .line 301
    .line 302
    invoke-direct {v2, v14, v14}, Lh71/h;-><init>(Lh71/x;Lh71/x;)V

    .line 303
    .line 304
    .line 305
    new-instance v7, Lh71/k;

    .line 306
    .line 307
    move-wide v10, v8

    .line 308
    move-wide v12, v8

    .line 309
    move-wide v14, v8

    .line 310
    move-wide/from16 v16, v8

    .line 311
    .line 312
    move-wide/from16 v18, v8

    .line 313
    .line 314
    move-wide/from16 v24, v8

    .line 315
    .line 316
    move-wide/from16 v20, v34

    .line 317
    .line 318
    invoke-direct/range {v7 .. v25}, Lh71/k;-><init>(JJJJJJJJJ)V

    .line 319
    .line 320
    .line 321
    new-instance v3, Lh71/g;

    .line 322
    .line 323
    invoke-direct {v3, v8, v9}, Lh71/g;-><init>(J)V

    .line 324
    .line 325
    .line 326
    new-instance v4, Lh71/i;

    .line 327
    .line 328
    move-wide/from16 v12, v32

    .line 329
    .line 330
    invoke-direct {v4, v12, v13, v0, v1}, Lh71/i;-><init>(JJ)V

    .line 331
    .line 332
    .line 333
    move-object/from16 v31, v4

    .line 334
    .line 335
    move-object/from16 v24, v28

    .line 336
    .line 337
    move-object/from16 v25, v29

    .line 338
    .line 339
    move-object/from16 v26, v30

    .line 340
    .line 341
    move-object/from16 v28, v2

    .line 342
    .line 343
    move-object/from16 v30, v3

    .line 344
    .line 345
    move-object/from16 v29, v7

    .line 346
    .line 347
    invoke-direct/range {v24 .. v31}, Lh71/l;-><init>(Lh71/e;Lh71/j;Lh71/f;Lh71/h;Lh71/k;Lh71/g;Lh71/i;)V

    .line 348
    .line 349
    .line 350
    sput-object v24, Li71/a;->a:Lh71/l;

    .line 351
    .line 352
    return-void
.end method

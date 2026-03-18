.class public final Lvv/y;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lvv/y;

.field public static final h:Lvv/y;

.field public static final i:Lvv/y;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lvv/y;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lvv/y;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lvv/y;->g:Lvv/y;

    .line 9
    .line 10
    new-instance v0, Lvv/y;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lvv/y;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lvv/y;->h:Lvv/y;

    .line 17
    .line 18
    new-instance v0, Lvv/y;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, Lvv/y;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lvv/y;->i:Lvv/y;

    .line 25
    .line 26
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lvv/y;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lvv/y;->f:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    check-cast v0, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    check-cast v0, Ll2/t;

    .line 20
    .line 21
    const v1, 0x56e04c3c

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ll2/t;->Z(I)V

    .line 25
    .line 26
    .line 27
    sget-object v1, Lvv/l0;->b:Ll2/e0;

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Le3/s;

    .line 34
    .line 35
    iget-wide v1, v1, Le3/s;->a:J

    .line 36
    .line 37
    const/4 v3, 0x0

    .line 38
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 39
    .line 40
    .line 41
    new-instance v0, Le3/s;

    .line 42
    .line 43
    invoke-direct {v0, v1, v2}, Le3/s;-><init>(J)V

    .line 44
    .line 45
    .line 46
    return-object v0

    .line 47
    :pswitch_0
    move-object/from16 v0, p1

    .line 48
    .line 49
    check-cast v0, Ll2/o;

    .line 50
    .line 51
    move-object/from16 v1, p2

    .line 52
    .line 53
    check-cast v1, Ljava/lang/Number;

    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 56
    .line 57
    .line 58
    check-cast v0, Ll2/t;

    .line 59
    .line 60
    const v1, -0x13db896b

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ll2/t;->Z(I)V

    .line 64
    .line 65
    .line 66
    sget-object v1, Lvv/l0;->a:Ll2/e0;

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    check-cast v1, Lg4/p0;

    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 76
    .line 77
    .line 78
    return-object v1

    .line 79
    :pswitch_1
    move-object/from16 v0, p1

    .line 80
    .line 81
    check-cast v0, Ljava/lang/Number;

    .line 82
    .line 83
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    move-object/from16 v1, p2

    .line 88
    .line 89
    check-cast v1, Lg4/p0;

    .line 90
    .line 91
    const-string v2, "textStyle"

    .line 92
    .line 93
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    if-eqz v0, :cond_5

    .line 97
    .line 98
    const/4 v2, 0x1

    .line 99
    if-eq v0, v2, :cond_4

    .line 100
    .line 101
    const/4 v3, 0x2

    .line 102
    const v4, 0x3f333333    # 0.7f

    .line 103
    .line 104
    .line 105
    if-eq v0, v3, :cond_3

    .line 106
    .line 107
    const/4 v3, 0x3

    .line 108
    if-eq v0, v3, :cond_2

    .line 109
    .line 110
    const/4 v2, 0x4

    .line 111
    if-eq v0, v2, :cond_1

    .line 112
    .line 113
    const/4 v2, 0x5

    .line 114
    if-eq v0, v2, :cond_0

    .line 115
    .line 116
    goto/16 :goto_2

    .line 117
    .line 118
    :cond_0
    sget-object v8, Lk4/x;->n:Lk4/x;

    .line 119
    .line 120
    invoke-virtual {v1}, Lg4/p0;->b()J

    .line 121
    .line 122
    .line 123
    move-result-wide v0

    .line 124
    const/high16 v2, 0x3f000000    # 0.5f

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, Le3/s;->b(JF)J

    .line 127
    .line 128
    .line 129
    move-result-wide v4

    .line 130
    new-instance v3, Lg4/p0;

    .line 131
    .line 132
    const-wide/16 v14, 0x0

    .line 133
    .line 134
    const v16, 0xfffffa

    .line 135
    .line 136
    .line 137
    const-wide/16 v6, 0x0

    .line 138
    .line 139
    const/4 v9, 0x0

    .line 140
    const/4 v10, 0x0

    .line 141
    const-wide/16 v11, 0x0

    .line 142
    .line 143
    const/4 v13, 0x0

    .line 144
    invoke-direct/range {v3 .. v16}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 145
    .line 146
    .line 147
    move-object v1, v3

    .line 148
    goto/16 :goto_2

    .line 149
    .line 150
    :cond_1
    const/16 v0, 0x12

    .line 151
    .line 152
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 153
    .line 154
    .line 155
    move-result-wide v8

    .line 156
    sget-object v10, Lk4/x;->n:Lk4/x;

    .line 157
    .line 158
    invoke-virtual {v1}, Lg4/p0;->b()J

    .line 159
    .line 160
    .line 161
    move-result-wide v0

    .line 162
    invoke-static {v0, v1, v4}, Le3/s;->b(JF)J

    .line 163
    .line 164
    .line 165
    move-result-wide v6

    .line 166
    new-instance v5, Lg4/p0;

    .line 167
    .line 168
    const-wide/16 v16, 0x0

    .line 169
    .line 170
    const v18, 0xfffff8

    .line 171
    .line 172
    .line 173
    const/4 v11, 0x0

    .line 174
    const/4 v12, 0x0

    .line 175
    const-wide/16 v13, 0x0

    .line 176
    .line 177
    const/4 v15, 0x0

    .line 178
    invoke-direct/range {v5 .. v18}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 179
    .line 180
    .line 181
    :goto_0
    move-object v1, v5

    .line 182
    goto/16 :goto_2

    .line 183
    .line 184
    :cond_2
    new-instance v6, Lg4/p0;

    .line 185
    .line 186
    const/16 v0, 0x14

    .line 187
    .line 188
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 189
    .line 190
    .line 191
    move-result-wide v9

    .line 192
    sget-object v11, Lk4/x;->n:Lk4/x;

    .line 193
    .line 194
    new-instance v12, Lk4/t;

    .line 195
    .line 196
    invoke-direct {v12, v2}, Lk4/t;-><init>(I)V

    .line 197
    .line 198
    .line 199
    const-wide/16 v17, 0x0

    .line 200
    .line 201
    const v19, 0xfffff1

    .line 202
    .line 203
    .line 204
    const-wide/16 v7, 0x0

    .line 205
    .line 206
    const/4 v13, 0x0

    .line 207
    const-wide/16 v14, 0x0

    .line 208
    .line 209
    const/16 v16, 0x0

    .line 210
    .line 211
    invoke-direct/range {v6 .. v19}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 212
    .line 213
    .line 214
    :goto_1
    move-object v1, v6

    .line 215
    goto :goto_2

    .line 216
    :cond_3
    const/16 v0, 0x16

    .line 217
    .line 218
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 219
    .line 220
    .line 221
    move-result-wide v8

    .line 222
    sget-object v10, Lk4/x;->n:Lk4/x;

    .line 223
    .line 224
    invoke-virtual {v1}, Lg4/p0;->b()J

    .line 225
    .line 226
    .line 227
    move-result-wide v0

    .line 228
    invoke-static {v0, v1, v4}, Le3/s;->b(JF)J

    .line 229
    .line 230
    .line 231
    move-result-wide v6

    .line 232
    new-instance v5, Lg4/p0;

    .line 233
    .line 234
    const-wide/16 v16, 0x0

    .line 235
    .line 236
    const v18, 0xfffff8

    .line 237
    .line 238
    .line 239
    const/4 v11, 0x0

    .line 240
    const/4 v12, 0x0

    .line 241
    const-wide/16 v13, 0x0

    .line 242
    .line 243
    const/4 v15, 0x0

    .line 244
    invoke-direct/range {v5 .. v18}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 245
    .line 246
    .line 247
    goto :goto_0

    .line 248
    :cond_4
    new-instance v6, Lg4/p0;

    .line 249
    .line 250
    const/16 v0, 0x1a

    .line 251
    .line 252
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 253
    .line 254
    .line 255
    move-result-wide v9

    .line 256
    sget-object v11, Lk4/x;->n:Lk4/x;

    .line 257
    .line 258
    const-wide/16 v17, 0x0

    .line 259
    .line 260
    const v19, 0xfffff9

    .line 261
    .line 262
    .line 263
    const-wide/16 v7, 0x0

    .line 264
    .line 265
    const/4 v12, 0x0

    .line 266
    const/4 v13, 0x0

    .line 267
    const-wide/16 v14, 0x0

    .line 268
    .line 269
    const/16 v16, 0x0

    .line 270
    .line 271
    invoke-direct/range {v6 .. v19}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 272
    .line 273
    .line 274
    goto :goto_1

    .line 275
    :cond_5
    new-instance v7, Lg4/p0;

    .line 276
    .line 277
    const/16 v0, 0x24

    .line 278
    .line 279
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 280
    .line 281
    .line 282
    move-result-wide v10

    .line 283
    sget-object v12, Lk4/x;->n:Lk4/x;

    .line 284
    .line 285
    const-wide/16 v18, 0x0

    .line 286
    .line 287
    const v20, 0xfffff9

    .line 288
    .line 289
    .line 290
    const-wide/16 v8, 0x0

    .line 291
    .line 292
    const/4 v13, 0x0

    .line 293
    const/4 v14, 0x0

    .line 294
    const-wide/16 v15, 0x0

    .line 295
    .line 296
    const/16 v17, 0x0

    .line 297
    .line 298
    invoke-direct/range {v7 .. v20}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 299
    .line 300
    .line 301
    move-object v1, v7

    .line 302
    :goto_2
    return-object v1

    .line 303
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

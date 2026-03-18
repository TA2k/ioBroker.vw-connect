.class public final Ltv/f;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# static fields
.field public static final g:Ltv/f;

.field public static final h:Ltv/f;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltv/f;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Ltv/f;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ltv/f;->g:Ltv/f;

    .line 9
    .line 10
    new-instance v0, Ltv/f;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Ltv/f;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Ltv/f;->h:Ltv/f;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Ltv/f;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Ltv/f;->f:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    check-cast v0, Lvv/m0;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Luv/q;

    .line 15
    .line 16
    move-object/from16 v2, p3

    .line 17
    .line 18
    check-cast v2, Ll2/o;

    .line 19
    .line 20
    move-object/from16 v3, p4

    .line 21
    .line 22
    check-cast v3, Ljava/lang/Number;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    const-string v4, "$this$FormattedList"

    .line 29
    .line 30
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v4, "astListItem"

    .line 34
    .line 35
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    and-int/lit8 v4, v3, 0xe

    .line 39
    .line 40
    if-nez v4, :cond_1

    .line 41
    .line 42
    move-object v4, v2

    .line 43
    check-cast v4, Ll2/t;

    .line 44
    .line 45
    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_0

    .line 50
    .line 51
    const/4 v4, 0x4

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 v4, 0x2

    .line 54
    :goto_0
    or-int/2addr v4, v3

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    move v4, v3

    .line 57
    :goto_1
    and-int/lit8 v3, v3, 0x70

    .line 58
    .line 59
    if-nez v3, :cond_3

    .line 60
    .line 61
    move-object v3, v2

    .line 62
    check-cast v3, Ll2/t;

    .line 63
    .line 64
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-eqz v3, :cond_2

    .line 69
    .line 70
    const/16 v3, 0x20

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    const/16 v3, 0x10

    .line 74
    .line 75
    :goto_2
    or-int/2addr v4, v3

    .line 76
    :cond_3
    and-int/lit16 v3, v4, 0x2db

    .line 77
    .line 78
    const/16 v5, 0x92

    .line 79
    .line 80
    if-ne v3, v5, :cond_5

    .line 81
    .line 82
    move-object v3, v2

    .line 83
    check-cast v3, Ll2/t;

    .line 84
    .line 85
    invoke-virtual {v3}, Ll2/t;->A()Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-nez v5, :cond_4

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 93
    .line 94
    .line 95
    goto :goto_4

    .line 96
    :cond_5
    :goto_3
    iget-object v3, v1, Luv/q;->b:Luv/r;

    .line 97
    .line 98
    iget-object v3, v3, Luv/r;->b:Luv/q;

    .line 99
    .line 100
    const/4 v5, 0x0

    .line 101
    if-nez v3, :cond_6

    .line 102
    .line 103
    move-object v14, v2

    .line 104
    check-cast v14, Ll2/t;

    .line 105
    .line 106
    const v0, 0x768bf3b

    .line 107
    .line 108
    .line 109
    invoke-virtual {v14, v0}, Ll2/t;->Z(I)V

    .line 110
    .line 111
    .line 112
    const/4 v15, 0x6

    .line 113
    const/16 v16, 0x1fe

    .line 114
    .line 115
    const-string v6, ""

    .line 116
    .line 117
    const/4 v7, 0x0

    .line 118
    const/4 v8, 0x0

    .line 119
    const/4 v9, 0x0

    .line 120
    const/4 v10, 0x0

    .line 121
    const/4 v11, 0x0

    .line 122
    const/4 v12, 0x0

    .line 123
    const/4 v13, 0x0

    .line 124
    invoke-static/range {v6 .. v16}, Lt1/l0;->d(Ljava/lang/String;Lx2/s;Lg4/p0;Lay0/k;IZIILl2/o;II)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v14, v5}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_6
    check-cast v2, Ll2/t;

    .line 132
    .line 133
    const v3, 0x768bf64

    .line 134
    .line 135
    .line 136
    invoke-virtual {v2, v3}, Ll2/t;->Z(I)V

    .line 137
    .line 138
    .line 139
    and-int/lit8 v3, v4, 0x7e

    .line 140
    .line 141
    invoke-static {v0, v1, v2, v3}, Llp/i0;->d(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v2, v5}, Ll2/t;->q(Z)V

    .line 145
    .line 146
    .line 147
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    return-object v0

    .line 150
    :pswitch_0
    move-object/from16 v0, p1

    .line 151
    .line 152
    check-cast v0, Lvv/m0;

    .line 153
    .line 154
    move-object/from16 v1, p2

    .line 155
    .line 156
    check-cast v1, Luv/q;

    .line 157
    .line 158
    move-object/from16 v2, p3

    .line 159
    .line 160
    check-cast v2, Ll2/o;

    .line 161
    .line 162
    move-object/from16 v3, p4

    .line 163
    .line 164
    check-cast v3, Ljava/lang/Number;

    .line 165
    .line 166
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    const-string v4, "$this$FormattedList"

    .line 171
    .line 172
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    const-string v4, "astListItem"

    .line 176
    .line 177
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    and-int/lit8 v4, v3, 0xe

    .line 181
    .line 182
    if-nez v4, :cond_8

    .line 183
    .line 184
    move-object v4, v2

    .line 185
    check-cast v4, Ll2/t;

    .line 186
    .line 187
    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v4

    .line 191
    if-eqz v4, :cond_7

    .line 192
    .line 193
    const/4 v4, 0x4

    .line 194
    goto :goto_5

    .line 195
    :cond_7
    const/4 v4, 0x2

    .line 196
    :goto_5
    or-int/2addr v4, v3

    .line 197
    goto :goto_6

    .line 198
    :cond_8
    move v4, v3

    .line 199
    :goto_6
    and-int/lit8 v3, v3, 0x70

    .line 200
    .line 201
    if-nez v3, :cond_a

    .line 202
    .line 203
    move-object v3, v2

    .line 204
    check-cast v3, Ll2/t;

    .line 205
    .line 206
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v3

    .line 210
    if-eqz v3, :cond_9

    .line 211
    .line 212
    const/16 v3, 0x20

    .line 213
    .line 214
    goto :goto_7

    .line 215
    :cond_9
    const/16 v3, 0x10

    .line 216
    .line 217
    :goto_7
    or-int/2addr v4, v3

    .line 218
    :cond_a
    and-int/lit16 v3, v4, 0x2db

    .line 219
    .line 220
    const/16 v5, 0x92

    .line 221
    .line 222
    if-ne v3, v5, :cond_c

    .line 223
    .line 224
    move-object v3, v2

    .line 225
    check-cast v3, Ll2/t;

    .line 226
    .line 227
    invoke-virtual {v3}, Ll2/t;->A()Z

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    if-nez v5, :cond_b

    .line 232
    .line 233
    goto :goto_8

    .line 234
    :cond_b
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 235
    .line 236
    .line 237
    goto :goto_9

    .line 238
    :cond_c
    :goto_8
    iget-object v3, v1, Luv/q;->b:Luv/r;

    .line 239
    .line 240
    iget-object v3, v3, Luv/r;->b:Luv/q;

    .line 241
    .line 242
    const/4 v5, 0x0

    .line 243
    if-nez v3, :cond_d

    .line 244
    .line 245
    move-object v14, v2

    .line 246
    check-cast v14, Ll2/t;

    .line 247
    .line 248
    const v0, 0x258af3dc

    .line 249
    .line 250
    .line 251
    invoke-virtual {v14, v0}, Ll2/t;->Z(I)V

    .line 252
    .line 253
    .line 254
    const/4 v15, 0x6

    .line 255
    const/16 v16, 0x1fe

    .line 256
    .line 257
    const-string v6, ""

    .line 258
    .line 259
    const/4 v7, 0x0

    .line 260
    const/4 v8, 0x0

    .line 261
    const/4 v9, 0x0

    .line 262
    const/4 v10, 0x0

    .line 263
    const/4 v11, 0x0

    .line 264
    const/4 v12, 0x0

    .line 265
    const/4 v13, 0x0

    .line 266
    invoke-static/range {v6 .. v16}, Lt1/l0;->d(Ljava/lang/String;Lx2/s;Lg4/p0;Lay0/k;IZIILl2/o;II)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {v14, v5}, Ll2/t;->q(Z)V

    .line 270
    .line 271
    .line 272
    goto :goto_9

    .line 273
    :cond_d
    check-cast v2, Ll2/t;

    .line 274
    .line 275
    const v3, 0x258af405

    .line 276
    .line 277
    .line 278
    invoke-virtual {v2, v3}, Ll2/t;->Z(I)V

    .line 279
    .line 280
    .line 281
    and-int/lit8 v3, v4, 0x7e

    .line 282
    .line 283
    invoke-static {v0, v1, v2, v3}, Llp/i0;->d(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 284
    .line 285
    .line 286
    invoke-virtual {v2, v5}, Ll2/t;->q(Z)V

    .line 287
    .line 288
    .line 289
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 290
    .line 291
    return-object v0

    .line 292
    nop

    .line 293
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

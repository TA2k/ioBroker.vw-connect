.class public final Lz9/d;
.super Lz9/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic q:I


# direct methods
.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lz9/d;->q:I

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lz9/g0;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static j(Ljava/lang/String;)[F
    .locals 2

    .line 1
    invoke-static {p0}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/4 v0, 0x1

    .line 14
    new-array v0, v0, [F

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aput p0, v0, v1

    .line 18
    .line 19
    return-object v0
.end method

.method public static k(Ljava/lang/String;)[I
    .locals 1

    .line 1
    sget-object v0, Lz9/g0;->b:Lz9/e;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    filled-new-array {p0}, [I

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static l(Ljava/lang/String;)[J
    .locals 3

    .line 1
    sget-object v0, Lz9/g0;->e:Lz9/e;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    const/4 p0, 0x1

    .line 14
    new-array p0, p0, [J

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    aput-wide v0, p0, v2

    .line 18
    .line 19
    return-object p0
.end method

.method public static m(Ljava/lang/String;)[Z
    .locals 2

    .line 1
    sget-object v0, Lz9/g0;->k:Lz9/e;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/4 v0, 0x1

    .line 14
    new-array v0, v0, [Z

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aput-boolean p0, v0, v1

    .line 18
    .line 19
    return-object v0
.end method


# virtual methods
.method public final a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "bundle"

    .line 7
    .line 8
    const-string v0, "key"

    .line 9
    .line 10
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-static {p1, p2}, Lkp/t;->h(Ljava/lang/String;Landroid/os/Bundle;)[Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-static {p0}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 33
    :goto_1
    return-object p0

    .line 34
    :pswitch_0
    const-string p0, "bundle"

    .line 35
    .line 36
    const-string v0, "key"

    .line 37
    .line 38
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_3

    .line 43
    .line 44
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_2

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    invoke-static {p1, p2}, Lkp/t;->h(Ljava/lang/String;Landroid/os/Bundle;)[Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    goto :goto_3

    .line 56
    :cond_3
    :goto_2
    const/4 p0, 0x0

    .line 57
    :goto_3
    return-object p0

    .line 58
    :pswitch_1
    const-string p0, "bundle"

    .line 59
    .line 60
    const-string v0, "key"

    .line 61
    .line 62
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    const/4 v0, 0x0

    .line 67
    if-eqz p0, :cond_6

    .line 68
    .line 69
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    if-eqz p0, :cond_4

    .line 74
    .line 75
    goto :goto_4

    .line 76
    :cond_4
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getLongArray(Ljava/lang/String;)[J

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    if-eqz p0, :cond_5

    .line 81
    .line 82
    invoke-static {p0}, Lmx0/n;->a0([J)Ljava/util/List;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    goto :goto_4

    .line 87
    :cond_5
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw v0

    .line 91
    :cond_6
    :goto_4
    return-object v0

    .line 92
    :pswitch_2
    const-string p0, "bundle"

    .line 93
    .line 94
    const-string v0, "key"

    .line 95
    .line 96
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    const/4 v0, 0x0

    .line 101
    if-eqz p0, :cond_9

    .line 102
    .line 103
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    if-eqz p0, :cond_7

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_7
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getLongArray(Ljava/lang/String;)[J

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-eqz p0, :cond_8

    .line 115
    .line 116
    move-object v0, p0

    .line 117
    goto :goto_5

    .line 118
    :cond_8
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw v0

    .line 122
    :cond_9
    :goto_5
    return-object v0

    .line 123
    :pswitch_3
    const-string p0, "bundle"

    .line 124
    .line 125
    const-string v0, "key"

    .line 126
    .line 127
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    const/4 v0, 0x0

    .line 132
    if-eqz p0, :cond_c

    .line 133
    .line 134
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    if-eqz p0, :cond_a

    .line 139
    .line 140
    goto :goto_6

    .line 141
    :cond_a
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getIntArray(Ljava/lang/String;)[I

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    if-eqz p0, :cond_b

    .line 146
    .line 147
    invoke-static {p0}, Lmx0/n;->Z([I)Ljava/util/List;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    goto :goto_6

    .line 152
    :cond_b
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw v0

    .line 156
    :cond_c
    :goto_6
    return-object v0

    .line 157
    :pswitch_4
    const-string p0, "bundle"

    .line 158
    .line 159
    const-string v0, "key"

    .line 160
    .line 161
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    const/4 v0, 0x0

    .line 166
    if-eqz p0, :cond_f

    .line 167
    .line 168
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 169
    .line 170
    .line 171
    move-result p0

    .line 172
    if-eqz p0, :cond_d

    .line 173
    .line 174
    goto :goto_7

    .line 175
    :cond_d
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getIntArray(Ljava/lang/String;)[I

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    if-eqz p0, :cond_e

    .line 180
    .line 181
    move-object v0, p0

    .line 182
    goto :goto_7

    .line 183
    :cond_e
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw v0

    .line 187
    :cond_f
    :goto_7
    return-object v0

    .line 188
    :pswitch_5
    const-string p0, "bundle"

    .line 189
    .line 190
    const-string v0, "key"

    .line 191
    .line 192
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 193
    .line 194
    .line 195
    move-result p0

    .line 196
    const/4 v0, 0x0

    .line 197
    if-eqz p0, :cond_12

    .line 198
    .line 199
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 200
    .line 201
    .line 202
    move-result p0

    .line 203
    if-eqz p0, :cond_10

    .line 204
    .line 205
    goto :goto_8

    .line 206
    :cond_10
    invoke-virtual {p2, p1}, Landroid/os/Bundle;->getFloatArray(Ljava/lang/String;)[F

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    if-eqz p0, :cond_11

    .line 211
    .line 212
    invoke-static {p0}, Lmx0/n;->Y([F)Ljava/util/List;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    goto :goto_8

    .line 217
    :cond_11
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    throw v0

    .line 221
    :cond_12
    :goto_8
    return-object v0

    .line 222
    :pswitch_6
    const-string p0, "bundle"

    .line 223
    .line 224
    const-string v0, "key"

    .line 225
    .line 226
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 227
    .line 228
    .line 229
    move-result p0

    .line 230
    const/4 v0, 0x0

    .line 231
    if-eqz p0, :cond_15

    .line 232
    .line 233
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 234
    .line 235
    .line 236
    move-result p0

    .line 237
    if-eqz p0, :cond_13

    .line 238
    .line 239
    goto :goto_9

    .line 240
    :cond_13
    invoke-virtual {p2, p1}, Landroid/os/Bundle;->getFloatArray(Ljava/lang/String;)[F

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    if-eqz p0, :cond_14

    .line 245
    .line 246
    move-object v0, p0

    .line 247
    goto :goto_9

    .line 248
    :cond_14
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    throw v0

    .line 252
    :cond_15
    :goto_9
    return-object v0

    .line 253
    :pswitch_7
    const-string p0, "bundle"

    .line 254
    .line 255
    const-string v0, "key"

    .line 256
    .line 257
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 258
    .line 259
    .line 260
    move-result p0

    .line 261
    const/4 v0, 0x0

    .line 262
    if-eqz p0, :cond_18

    .line 263
    .line 264
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 265
    .line 266
    .line 267
    move-result p0

    .line 268
    if-eqz p0, :cond_16

    .line 269
    .line 270
    goto :goto_a

    .line 271
    :cond_16
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getBooleanArray(Ljava/lang/String;)[Z

    .line 272
    .line 273
    .line 274
    move-result-object p0

    .line 275
    if-eqz p0, :cond_17

    .line 276
    .line 277
    invoke-static {p0}, Lmx0/n;->c0([Z)Ljava/util/List;

    .line 278
    .line 279
    .line 280
    move-result-object v0

    .line 281
    goto :goto_a

    .line 282
    :cond_17
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    throw v0

    .line 286
    :cond_18
    :goto_a
    return-object v0

    .line 287
    :pswitch_8
    const-string p0, "bundle"

    .line 288
    .line 289
    const-string v0, "key"

    .line 290
    .line 291
    invoke-static {p2, p0, p1, v0, p1}, Lz9/c;->d(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z

    .line 292
    .line 293
    .line 294
    move-result p0

    .line 295
    const/4 v0, 0x0

    .line 296
    if-eqz p0, :cond_1b

    .line 297
    .line 298
    invoke-static {p1, p2}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 299
    .line 300
    .line 301
    move-result p0

    .line 302
    if-eqz p0, :cond_19

    .line 303
    .line 304
    goto :goto_b

    .line 305
    :cond_19
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getBooleanArray(Ljava/lang/String;)[Z

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    if-eqz p0, :cond_1a

    .line 310
    .line 311
    move-object v0, p0

    .line 312
    goto :goto_b

    .line 313
    :cond_1a
    invoke-static {p1}, Lkp/u;->a(Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    throw v0

    .line 317
    :cond_1b
    :goto_b
    return-object v0

    .line 318
    nop

    .line 319
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "List<String>"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "string[]"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "List<Long>"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    const-string p0, "long[]"

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    const-string p0, "List<Int>"

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    const-string p0, "integer[]"

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    const-string p0, "List<Float>"

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    const-string p0, "float[]"

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    const-string p0, "List<Boolean>"

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    const-string p0, "boolean[]"

    .line 34
    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    check-cast p1, Ljava/util/Collection;

    .line 11
    .line 12
    invoke-static {p2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/lang/Iterable;

    .line 17
    .line 18
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-static {p2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    :goto_0
    return-object p0

    .line 28
    :pswitch_0
    check-cast p1, [Ljava/lang/String;

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    filled-new-array {p2}, [Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {p1, p0}, Lmx0/n;->O([Ljava/lang/Object;[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, [Ljava/lang/String;

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    filled-new-array {p2}, [Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    :goto_1
    return-object p0

    .line 48
    :pswitch_1
    check-cast p1, Ljava/util/List;

    .line 49
    .line 50
    sget-object p0, Lz9/g0;->e:Lz9/e;

    .line 51
    .line 52
    if-eqz p1, :cond_2

    .line 53
    .line 54
    check-cast p1, Ljava/util/Collection;

    .line 55
    .line 56
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Ljava/lang/Iterable;

    .line 65
    .line 66
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    goto :goto_2

    .line 71
    :cond_2
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    :goto_2
    return-object p0

    .line 80
    :pswitch_2
    check-cast p1, [J

    .line 81
    .line 82
    if-eqz p1, :cond_3

    .line 83
    .line 84
    invoke-static {p2}, Lz9/d;->l(Ljava/lang/String;)[J

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    array-length p2, p1

    .line 89
    add-int/lit8 v0, p2, 0x1

    .line 90
    .line 91
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    const/4 v0, 0x0

    .line 96
    const/4 v1, 0x1

    .line 97
    invoke-static {p0, v0, p1, p2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 98
    .line 99
    .line 100
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_3
    invoke-static {p2}, Lz9/d;->l(Ljava/lang/String;)[J

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    :goto_3
    return-object p1

    .line 109
    :pswitch_3
    check-cast p1, Ljava/util/List;

    .line 110
    .line 111
    sget-object p0, Lz9/g0;->b:Lz9/e;

    .line 112
    .line 113
    if-eqz p1, :cond_4

    .line 114
    .line 115
    check-cast p1, Ljava/util/Collection;

    .line 116
    .line 117
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    check-cast p0, Ljava/lang/Iterable;

    .line 126
    .line 127
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    goto :goto_4

    .line 132
    :cond_4
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    :goto_4
    return-object p0

    .line 141
    :pswitch_4
    check-cast p1, [I

    .line 142
    .line 143
    if-eqz p1, :cond_5

    .line 144
    .line 145
    invoke-static {p2}, Lz9/d;->k(Ljava/lang/String;)[I

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    array-length p2, p1

    .line 150
    add-int/lit8 v0, p2, 0x1

    .line 151
    .line 152
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([II)[I

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    const/4 v0, 0x0

    .line 157
    const/4 v1, 0x1

    .line 158
    invoke-static {p0, v0, p1, p2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 159
    .line 160
    .line 161
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    goto :goto_5

    .line 165
    :cond_5
    invoke-static {p2}, Lz9/d;->k(Ljava/lang/String;)[I

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    :goto_5
    return-object p1

    .line 170
    :pswitch_5
    check-cast p1, Ljava/util/List;

    .line 171
    .line 172
    if-eqz p1, :cond_6

    .line 173
    .line 174
    check-cast p1, Ljava/util/Collection;

    .line 175
    .line 176
    invoke-static {p2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 177
    .line 178
    .line 179
    move-result p0

    .line 180
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    check-cast p0, Ljava/lang/Iterable;

    .line 189
    .line 190
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    goto :goto_6

    .line 195
    :cond_6
    invoke-static {p2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 196
    .line 197
    .line 198
    move-result p0

    .line 199
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    :goto_6
    return-object p0

    .line 208
    :pswitch_6
    check-cast p1, [F

    .line 209
    .line 210
    if-eqz p1, :cond_7

    .line 211
    .line 212
    invoke-static {p2}, Lz9/d;->j(Ljava/lang/String;)[F

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    array-length p2, p1

    .line 217
    add-int/lit8 v0, p2, 0x1

    .line 218
    .line 219
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([FI)[F

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    const/4 v0, 0x0

    .line 224
    const/4 v1, 0x1

    .line 225
    invoke-static {p0, v0, p1, p2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 226
    .line 227
    .line 228
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    goto :goto_7

    .line 232
    :cond_7
    invoke-static {p2}, Lz9/d;->j(Ljava/lang/String;)[F

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    :goto_7
    return-object p1

    .line 237
    :pswitch_7
    check-cast p1, Ljava/util/List;

    .line 238
    .line 239
    sget-object p0, Lz9/g0;->k:Lz9/e;

    .line 240
    .line 241
    if-eqz p1, :cond_8

    .line 242
    .line 243
    check-cast p1, Ljava/util/Collection;

    .line 244
    .line 245
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object p0

    .line 249
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 250
    .line 251
    .line 252
    move-result-object p0

    .line 253
    check-cast p0, Ljava/lang/Iterable;

    .line 254
    .line 255
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    goto :goto_8

    .line 260
    :cond_8
    invoke-virtual {p0, p2}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 265
    .line 266
    .line 267
    move-result-object p0

    .line 268
    :goto_8
    return-object p0

    .line 269
    :pswitch_8
    check-cast p1, [Z

    .line 270
    .line 271
    if-eqz p1, :cond_9

    .line 272
    .line 273
    invoke-static {p2}, Lz9/d;->m(Ljava/lang/String;)[Z

    .line 274
    .line 275
    .line 276
    move-result-object p0

    .line 277
    array-length p2, p1

    .line 278
    add-int/lit8 v0, p2, 0x1

    .line 279
    .line 280
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([ZI)[Z

    .line 281
    .line 282
    .line 283
    move-result-object p1

    .line 284
    const/4 v0, 0x0

    .line 285
    const/4 v1, 0x1

    .line 286
    invoke-static {p0, v0, p1, p2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 287
    .line 288
    .line 289
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    goto :goto_9

    .line 293
    :cond_9
    invoke-static {p2}, Lz9/d;->m(Ljava/lang/String;)[Z

    .line 294
    .line 295
    .line 296
    move-result-object p1

    .line 297
    :goto_9
    return-object p1

    .line 298
    nop

    .line 299
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    filled-new-array {p1}, [Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_1
    sget-object p0, Lz9/g0;->e:Lz9/e;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_2
    invoke-static {p1}, Lz9/d;->l(Ljava/lang/String;)[J

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_3
    sget-object p0, Lz9/g0;->b:Lz9/e;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_4
    invoke-static {p1}, Lz9/d;->k(Ljava/lang/String;)[I

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_5
    invoke-static {p1}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_6
    invoke-static {p1}, Lz9/d;->j(Ljava/lang/String;)[F

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :pswitch_7
    sget-object p0, Lz9/g0;->k:Lz9/e;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lz9/e;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0

    .line 77
    :pswitch_8
    invoke-static {p1}, Lz9/d;->m(Ljava/lang/String;)[Z

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p3, Ljava/util/List;

    .line 7
    .line 8
    const-string p0, "key"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    if-eqz p3, :cond_0

    .line 14
    .line 15
    check-cast p3, Ljava/util/Collection;

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    new-array p0, p0, [Ljava/lang/String;

    .line 19
    .line 20
    invoke-interface {p3, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, [Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {p1, p2, p0}, Lkp/v;->f(Landroid/os/Bundle;Ljava/lang/String;[Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    return-void

    .line 34
    :pswitch_0
    check-cast p3, [Ljava/lang/String;

    .line 35
    .line 36
    const-string p0, "key"

    .line 37
    .line 38
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    if-eqz p3, :cond_1

    .line 42
    .line 43
    invoke-static {p1, p2, p3}, Lkp/v;->f(Landroid/os/Bundle;Ljava/lang/String;[Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 48
    .line 49
    .line 50
    :goto_1
    return-void

    .line 51
    :pswitch_1
    check-cast p3, Ljava/util/List;

    .line 52
    .line 53
    const-string p0, "key"

    .line 54
    .line 55
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    if-eqz p3, :cond_2

    .line 59
    .line 60
    check-cast p3, Ljava/util/Collection;

    .line 61
    .line 62
    invoke-static {p3}, Lmx0/q;->y0(Ljava/util/Collection;)[J

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-virtual {p1, p2, p0}, Landroid/os/BaseBundle;->putLongArray(Ljava/lang/String;[J)V

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_2
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 71
    .line 72
    .line 73
    :goto_2
    return-void

    .line 74
    :pswitch_2
    check-cast p3, [J

    .line 75
    .line 76
    const-string p0, "key"

    .line 77
    .line 78
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    if-eqz p3, :cond_3

    .line 82
    .line 83
    invoke-virtual {p1, p2, p3}, Landroid/os/BaseBundle;->putLongArray(Ljava/lang/String;[J)V

    .line 84
    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_3
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 88
    .line 89
    .line 90
    :goto_3
    return-void

    .line 91
    :pswitch_3
    check-cast p3, Ljava/util/List;

    .line 92
    .line 93
    const-string p0, "key"

    .line 94
    .line 95
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    if-eqz p3, :cond_4

    .line 99
    .line 100
    check-cast p3, Ljava/util/Collection;

    .line 101
    .line 102
    invoke-static {p3}, Lmx0/q;->w0(Ljava/util/Collection;)[I

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-virtual {p1, p2, p0}, Landroid/os/BaseBundle;->putIntArray(Ljava/lang/String;[I)V

    .line 107
    .line 108
    .line 109
    :cond_4
    return-void

    .line 110
    :pswitch_4
    check-cast p3, [I

    .line 111
    .line 112
    const-string p0, "key"

    .line 113
    .line 114
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    if-eqz p3, :cond_5

    .line 118
    .line 119
    invoke-virtual {p1, p2, p3}, Landroid/os/BaseBundle;->putIntArray(Ljava/lang/String;[I)V

    .line 120
    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_5
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 124
    .line 125
    .line 126
    :goto_4
    return-void

    .line 127
    :pswitch_5
    check-cast p3, Ljava/util/List;

    .line 128
    .line 129
    const-string p0, "key"

    .line 130
    .line 131
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    if-eqz p3, :cond_6

    .line 135
    .line 136
    check-cast p3, Ljava/util/Collection;

    .line 137
    .line 138
    invoke-static {p3}, Lmx0/q;->v0(Ljava/util/Collection;)[F

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-virtual {p1, p2, p0}, Landroid/os/Bundle;->putFloatArray(Ljava/lang/String;[F)V

    .line 143
    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_6
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 147
    .line 148
    .line 149
    :goto_5
    return-void

    .line 150
    :pswitch_6
    check-cast p3, [F

    .line 151
    .line 152
    const-string p0, "key"

    .line 153
    .line 154
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    if-eqz p3, :cond_7

    .line 158
    .line 159
    invoke-virtual {p1, p2, p3}, Landroid/os/Bundle;->putFloatArray(Ljava/lang/String;[F)V

    .line 160
    .line 161
    .line 162
    goto :goto_6

    .line 163
    :cond_7
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 164
    .line 165
    .line 166
    :goto_6
    return-void

    .line 167
    :pswitch_7
    check-cast p3, Ljava/util/List;

    .line 168
    .line 169
    const-string p0, "key"

    .line 170
    .line 171
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    if-eqz p3, :cond_8

    .line 175
    .line 176
    check-cast p3, Ljava/util/Collection;

    .line 177
    .line 178
    invoke-static {p3}, Lmx0/q;->s0(Ljava/util/Collection;)[Z

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    invoke-virtual {p1, p2, p0}, Landroid/os/BaseBundle;->putBooleanArray(Ljava/lang/String;[Z)V

    .line 183
    .line 184
    .line 185
    goto :goto_7

    .line 186
    :cond_8
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 187
    .line 188
    .line 189
    :goto_7
    return-void

    .line 190
    :pswitch_8
    check-cast p3, [Z

    .line 191
    .line 192
    const-string p0, "key"

    .line 193
    .line 194
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    if-eqz p3, :cond_9

    .line 198
    .line 199
    invoke-virtual {p1, p2, p3}, Landroid/os/BaseBundle;->putBooleanArray(Ljava/lang/String;[Z)V

    .line 200
    .line 201
    .line 202
    goto :goto_8

    .line 203
    :cond_9
    invoke-static {p2, p1}, Lkp/v;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 204
    .line 205
    .line 206
    :goto_8
    return-void

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final g(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 6

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    check-cast p2, Ljava/util/List;

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    check-cast p1, Ljava/util/Collection;

    .line 15
    .line 16
    new-array v1, v0, [Ljava/lang/String;

    .line 17
    .line 18
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, [Ljava/lang/String;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move-object p1, p0

    .line 26
    :goto_0
    if-eqz p2, :cond_1

    .line 27
    .line 28
    check-cast p2, Ljava/util/Collection;

    .line 29
    .line 30
    new-array p0, v0, [Ljava/lang/String;

    .line 31
    .line 32
    invoke-interface {p2, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, [Ljava/lang/String;

    .line 37
    .line 38
    :cond_1
    invoke-static {p1, p0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    return p0

    .line 43
    :pswitch_0
    check-cast p1, [Ljava/lang/String;

    .line 44
    .line 45
    check-cast p2, [Ljava/lang/String;

    .line 46
    .line 47
    invoke-static {p1, p2}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0

    .line 52
    :pswitch_1
    check-cast p1, Ljava/util/List;

    .line 53
    .line 54
    check-cast p2, Ljava/util/List;

    .line 55
    .line 56
    const/4 p0, 0x0

    .line 57
    const/4 v0, 0x0

    .line 58
    if-eqz p1, :cond_2

    .line 59
    .line 60
    check-cast p1, Ljava/util/Collection;

    .line 61
    .line 62
    new-array v1, v0, [Ljava/lang/Long;

    .line 63
    .line 64
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    check-cast p1, [Ljava/lang/Long;

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    move-object p1, p0

    .line 72
    :goto_1
    if-eqz p2, :cond_3

    .line 73
    .line 74
    check-cast p2, Ljava/util/Collection;

    .line 75
    .line 76
    new-array p0, v0, [Ljava/lang/Long;

    .line 77
    .line 78
    invoke-interface {p2, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, [Ljava/lang/Long;

    .line 83
    .line 84
    :cond_3
    invoke-static {p1, p0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    return p0

    .line 89
    :pswitch_2
    check-cast p1, [J

    .line 90
    .line 91
    check-cast p2, [J

    .line 92
    .line 93
    const/4 p0, 0x0

    .line 94
    const/4 v0, 0x0

    .line 95
    if-eqz p1, :cond_4

    .line 96
    .line 97
    array-length v1, p1

    .line 98
    new-array v1, v1, [Ljava/lang/Long;

    .line 99
    .line 100
    array-length v2, p1

    .line 101
    move v3, p0

    .line 102
    :goto_2
    if-ge v3, v2, :cond_5

    .line 103
    .line 104
    aget-wide v4, p1, v3

    .line 105
    .line 106
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    aput-object v4, v1, v3

    .line 111
    .line 112
    add-int/lit8 v3, v3, 0x1

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_4
    move-object v1, v0

    .line 116
    :cond_5
    if-eqz p2, :cond_6

    .line 117
    .line 118
    array-length p1, p2

    .line 119
    new-array v0, p1, [Ljava/lang/Long;

    .line 120
    .line 121
    array-length p1, p2

    .line 122
    :goto_3
    if-ge p0, p1, :cond_6

    .line 123
    .line 124
    aget-wide v2, p2, p0

    .line 125
    .line 126
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    aput-object v2, v0, p0

    .line 131
    .line 132
    add-int/lit8 p0, p0, 0x1

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_6
    invoke-static {v1, v0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    return p0

    .line 140
    :pswitch_3
    check-cast p1, Ljava/util/List;

    .line 141
    .line 142
    check-cast p2, Ljava/util/List;

    .line 143
    .line 144
    const/4 p0, 0x0

    .line 145
    const/4 v0, 0x0

    .line 146
    if-eqz p1, :cond_7

    .line 147
    .line 148
    check-cast p1, Ljava/util/Collection;

    .line 149
    .line 150
    new-array v1, v0, [Ljava/lang/Integer;

    .line 151
    .line 152
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    check-cast p1, [Ljava/lang/Integer;

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_7
    move-object p1, p0

    .line 160
    :goto_4
    if-eqz p2, :cond_8

    .line 161
    .line 162
    check-cast p2, Ljava/util/Collection;

    .line 163
    .line 164
    new-array p0, v0, [Ljava/lang/Integer;

    .line 165
    .line 166
    invoke-interface {p2, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    check-cast p0, [Ljava/lang/Integer;

    .line 171
    .line 172
    :cond_8
    invoke-static {p1, p0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result p0

    .line 176
    return p0

    .line 177
    :pswitch_4
    check-cast p1, [I

    .line 178
    .line 179
    check-cast p2, [I

    .line 180
    .line 181
    const/4 p0, 0x0

    .line 182
    const/4 v0, 0x0

    .line 183
    if-eqz p1, :cond_9

    .line 184
    .line 185
    array-length v1, p1

    .line 186
    new-array v1, v1, [Ljava/lang/Integer;

    .line 187
    .line 188
    array-length v2, p1

    .line 189
    move v3, p0

    .line 190
    :goto_5
    if-ge v3, v2, :cond_a

    .line 191
    .line 192
    aget v4, p1, v3

    .line 193
    .line 194
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    aput-object v4, v1, v3

    .line 199
    .line 200
    add-int/lit8 v3, v3, 0x1

    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_9
    move-object v1, v0

    .line 204
    :cond_a
    if-eqz p2, :cond_b

    .line 205
    .line 206
    array-length p1, p2

    .line 207
    new-array v0, p1, [Ljava/lang/Integer;

    .line 208
    .line 209
    array-length p1, p2

    .line 210
    :goto_6
    if-ge p0, p1, :cond_b

    .line 211
    .line 212
    aget v2, p2, p0

    .line 213
    .line 214
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    aput-object v2, v0, p0

    .line 219
    .line 220
    add-int/lit8 p0, p0, 0x1

    .line 221
    .line 222
    goto :goto_6

    .line 223
    :cond_b
    invoke-static {v1, v0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result p0

    .line 227
    return p0

    .line 228
    :pswitch_5
    check-cast p1, Ljava/util/List;

    .line 229
    .line 230
    check-cast p2, Ljava/util/List;

    .line 231
    .line 232
    const/4 p0, 0x0

    .line 233
    const/4 v0, 0x0

    .line 234
    if-eqz p1, :cond_c

    .line 235
    .line 236
    check-cast p1, Ljava/util/Collection;

    .line 237
    .line 238
    new-array v1, v0, [Ljava/lang/Float;

    .line 239
    .line 240
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    check-cast p1, [Ljava/lang/Float;

    .line 245
    .line 246
    goto :goto_7

    .line 247
    :cond_c
    move-object p1, p0

    .line 248
    :goto_7
    if-eqz p2, :cond_d

    .line 249
    .line 250
    check-cast p2, Ljava/util/Collection;

    .line 251
    .line 252
    new-array p0, v0, [Ljava/lang/Float;

    .line 253
    .line 254
    invoke-interface {p2, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    check-cast p0, [Ljava/lang/Float;

    .line 259
    .line 260
    :cond_d
    invoke-static {p1, p0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result p0

    .line 264
    return p0

    .line 265
    :pswitch_6
    check-cast p1, [F

    .line 266
    .line 267
    check-cast p2, [F

    .line 268
    .line 269
    const/4 p0, 0x0

    .line 270
    const/4 v0, 0x0

    .line 271
    if-eqz p1, :cond_e

    .line 272
    .line 273
    array-length v1, p1

    .line 274
    new-array v1, v1, [Ljava/lang/Float;

    .line 275
    .line 276
    array-length v2, p1

    .line 277
    move v3, p0

    .line 278
    :goto_8
    if-ge v3, v2, :cond_f

    .line 279
    .line 280
    aget v4, p1, v3

    .line 281
    .line 282
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    aput-object v4, v1, v3

    .line 287
    .line 288
    add-int/lit8 v3, v3, 0x1

    .line 289
    .line 290
    goto :goto_8

    .line 291
    :cond_e
    move-object v1, v0

    .line 292
    :cond_f
    if-eqz p2, :cond_10

    .line 293
    .line 294
    array-length p1, p2

    .line 295
    new-array v0, p1, [Ljava/lang/Float;

    .line 296
    .line 297
    array-length p1, p2

    .line 298
    :goto_9
    if-ge p0, p1, :cond_10

    .line 299
    .line 300
    aget v2, p2, p0

    .line 301
    .line 302
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 303
    .line 304
    .line 305
    move-result-object v2

    .line 306
    aput-object v2, v0, p0

    .line 307
    .line 308
    add-int/lit8 p0, p0, 0x1

    .line 309
    .line 310
    goto :goto_9

    .line 311
    :cond_10
    invoke-static {v1, v0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 312
    .line 313
    .line 314
    move-result p0

    .line 315
    return p0

    .line 316
    :pswitch_7
    check-cast p1, Ljava/util/List;

    .line 317
    .line 318
    check-cast p2, Ljava/util/List;

    .line 319
    .line 320
    const/4 p0, 0x0

    .line 321
    const/4 v0, 0x0

    .line 322
    if-eqz p1, :cond_11

    .line 323
    .line 324
    check-cast p1, Ljava/util/Collection;

    .line 325
    .line 326
    new-array v1, v0, [Ljava/lang/Boolean;

    .line 327
    .line 328
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object p1

    .line 332
    check-cast p1, [Ljava/lang/Boolean;

    .line 333
    .line 334
    goto :goto_a

    .line 335
    :cond_11
    move-object p1, p0

    .line 336
    :goto_a
    if-eqz p2, :cond_12

    .line 337
    .line 338
    check-cast p2, Ljava/util/Collection;

    .line 339
    .line 340
    new-array p0, v0, [Ljava/lang/Boolean;

    .line 341
    .line 342
    invoke-interface {p2, p0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object p0

    .line 346
    check-cast p0, [Ljava/lang/Boolean;

    .line 347
    .line 348
    :cond_12
    invoke-static {p1, p0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 349
    .line 350
    .line 351
    move-result p0

    .line 352
    return p0

    .line 353
    :pswitch_8
    check-cast p1, [Z

    .line 354
    .line 355
    check-cast p2, [Z

    .line 356
    .line 357
    const/4 p0, 0x0

    .line 358
    const/4 v0, 0x0

    .line 359
    if-eqz p1, :cond_13

    .line 360
    .line 361
    array-length v1, p1

    .line 362
    new-array v1, v1, [Ljava/lang/Boolean;

    .line 363
    .line 364
    array-length v2, p1

    .line 365
    move v3, p0

    .line 366
    :goto_b
    if-ge v3, v2, :cond_14

    .line 367
    .line 368
    aget-boolean v4, p1, v3

    .line 369
    .line 370
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 371
    .line 372
    .line 373
    move-result-object v4

    .line 374
    aput-object v4, v1, v3

    .line 375
    .line 376
    add-int/lit8 v3, v3, 0x1

    .line 377
    .line 378
    goto :goto_b

    .line 379
    :cond_13
    move-object v1, v0

    .line 380
    :cond_14
    if-eqz p2, :cond_15

    .line 381
    .line 382
    array-length p1, p2

    .line 383
    new-array v0, p1, [Ljava/lang/Boolean;

    .line 384
    .line 385
    array-length p1, p2

    .line 386
    :goto_c
    if-ge p0, p1, :cond_15

    .line 387
    .line 388
    aget-boolean v2, p2, p0

    .line 389
    .line 390
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 391
    .line 392
    .line 393
    move-result-object v2

    .line 394
    aput-object v2, v0, p0

    .line 395
    .line 396
    add-int/lit8 p0, p0, 0x1

    .line 397
    .line 398
    goto :goto_c

    .line 399
    :cond_15
    invoke-static {v1, v0}, Lmx0/n;->f([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 400
    .line 401
    .line 402
    move-result p0

    .line 403
    return p0

    .line 404
    nop

    .line 405
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final h()Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const/4 p0, 0x0

    .line 10
    new-array p0, p0, [Ljava/lang/String;

    .line 11
    .line 12
    return-object p0

    .line 13
    :pswitch_1
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_2
    const/4 p0, 0x0

    .line 17
    new-array p0, p0, [J

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_3
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_4
    const/4 p0, 0x0

    .line 24
    new-array p0, p0, [I

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_5
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_6
    const/4 p0, 0x0

    .line 31
    new-array p0, p0, [F

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_7
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_8
    const/4 p0, 0x0

    .line 38
    new-array p0, p0, [Z

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Ljava/lang/Object;)Ljava/util/List;
    .locals 3

    .line 1
    iget p0, p0, Lz9/d;->q:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    check-cast p1, Ljava/lang/Iterable;

    .line 11
    .line 12
    new-instance p0, Ljava/util/ArrayList;

    .line 13
    .line 14
    const/16 v0, 0xa

    .line 15
    .line 16
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v0}, Lz9/h0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 48
    .line 49
    :cond_1
    return-object p0

    .line 50
    :pswitch_0
    check-cast p1, [Ljava/lang/String;

    .line 51
    .line 52
    if-eqz p1, :cond_2

    .line 53
    .line 54
    new-instance p0, Ljava/util/ArrayList;

    .line 55
    .line 56
    array-length v0, p1

    .line 57
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 58
    .line 59
    .line 60
    array-length v0, p1

    .line 61
    const/4 v1, 0x0

    .line 62
    :goto_1
    if-ge v1, v0, :cond_3

    .line 63
    .line 64
    aget-object v2, p1, v1

    .line 65
    .line 66
    invoke-static {v2}, Lz9/h0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    add-int/lit8 v1, v1, 0x1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 77
    .line 78
    :cond_3
    return-object p0

    .line 79
    :pswitch_1
    check-cast p1, Ljava/util/List;

    .line 80
    .line 81
    if-eqz p1, :cond_4

    .line 82
    .line 83
    check-cast p1, Ljava/lang/Iterable;

    .line 84
    .line 85
    new-instance p0, Ljava/util/ArrayList;

    .line 86
    .line 87
    const/16 v0, 0xa

    .line 88
    .line 89
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 94
    .line 95
    .line 96
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-eqz v0, :cond_5

    .line 105
    .line 106
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    check-cast v0, Ljava/lang/Number;

    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 113
    .line 114
    .line 115
    move-result-wide v0

    .line 116
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_4
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 125
    .line 126
    :cond_5
    return-object p0

    .line 127
    :pswitch_2
    check-cast p1, [J

    .line 128
    .line 129
    if-eqz p1, :cond_6

    .line 130
    .line 131
    invoke-static {p1}, Lmx0/n;->a0([J)Ljava/util/List;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    check-cast p0, Ljava/lang/Iterable;

    .line 136
    .line 137
    new-instance p1, Ljava/util/ArrayList;

    .line 138
    .line 139
    const/16 v0, 0xa

    .line 140
    .line 141
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 146
    .line 147
    .line 148
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    if-eqz v0, :cond_7

    .line 157
    .line 158
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    check-cast v0, Ljava/lang/Number;

    .line 163
    .line 164
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 165
    .line 166
    .line 167
    move-result-wide v0

    .line 168
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    goto :goto_3

    .line 176
    :cond_6
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 177
    .line 178
    :cond_7
    return-object p1

    .line 179
    :pswitch_3
    check-cast p1, Ljava/util/List;

    .line 180
    .line 181
    if-eqz p1, :cond_8

    .line 182
    .line 183
    check-cast p1, Ljava/lang/Iterable;

    .line 184
    .line 185
    new-instance p0, Ljava/util/ArrayList;

    .line 186
    .line 187
    const/16 v0, 0xa

    .line 188
    .line 189
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 194
    .line 195
    .line 196
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 201
    .line 202
    .line 203
    move-result v0

    .line 204
    if-eqz v0, :cond_9

    .line 205
    .line 206
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    check-cast v0, Ljava/lang/Number;

    .line 211
    .line 212
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 213
    .line 214
    .line 215
    move-result v0

    .line 216
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_8
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 225
    .line 226
    :cond_9
    return-object p0

    .line 227
    :pswitch_4
    check-cast p1, [I

    .line 228
    .line 229
    if-eqz p1, :cond_a

    .line 230
    .line 231
    invoke-static {p1}, Lmx0/n;->Z([I)Ljava/util/List;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    check-cast p0, Ljava/lang/Iterable;

    .line 236
    .line 237
    new-instance p1, Ljava/util/ArrayList;

    .line 238
    .line 239
    const/16 v0, 0xa

    .line 240
    .line 241
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 242
    .line 243
    .line 244
    move-result v0

    .line 245
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 246
    .line 247
    .line 248
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    :goto_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    if-eqz v0, :cond_b

    .line 257
    .line 258
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    check-cast v0, Ljava/lang/Number;

    .line 263
    .line 264
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 265
    .line 266
    .line 267
    move-result v0

    .line 268
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    goto :goto_5

    .line 276
    :cond_a
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 277
    .line 278
    :cond_b
    return-object p1

    .line 279
    :pswitch_5
    check-cast p1, Ljava/util/List;

    .line 280
    .line 281
    if-eqz p1, :cond_c

    .line 282
    .line 283
    check-cast p1, Ljava/lang/Iterable;

    .line 284
    .line 285
    new-instance p0, Ljava/util/ArrayList;

    .line 286
    .line 287
    const/16 v0, 0xa

    .line 288
    .line 289
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 290
    .line 291
    .line 292
    move-result v0

    .line 293
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 294
    .line 295
    .line 296
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 297
    .line 298
    .line 299
    move-result-object p1

    .line 300
    :goto_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 301
    .line 302
    .line 303
    move-result v0

    .line 304
    if-eqz v0, :cond_d

    .line 305
    .line 306
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    check-cast v0, Ljava/lang/Number;

    .line 311
    .line 312
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 313
    .line 314
    .line 315
    move-result v0

    .line 316
    invoke-static {v0}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 321
    .line 322
    .line 323
    goto :goto_6

    .line 324
    :cond_c
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 325
    .line 326
    :cond_d
    return-object p0

    .line 327
    :pswitch_6
    check-cast p1, [F

    .line 328
    .line 329
    if-eqz p1, :cond_e

    .line 330
    .line 331
    invoke-static {p1}, Lmx0/n;->Y([F)Ljava/util/List;

    .line 332
    .line 333
    .line 334
    move-result-object p0

    .line 335
    check-cast p0, Ljava/lang/Iterable;

    .line 336
    .line 337
    new-instance p1, Ljava/util/ArrayList;

    .line 338
    .line 339
    const/16 v0, 0xa

    .line 340
    .line 341
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 342
    .line 343
    .line 344
    move-result v0

    .line 345
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 346
    .line 347
    .line 348
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 349
    .line 350
    .line 351
    move-result-object p0

    .line 352
    :goto_7
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 353
    .line 354
    .line 355
    move-result v0

    .line 356
    if-eqz v0, :cond_f

    .line 357
    .line 358
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    move-result-object v0

    .line 362
    check-cast v0, Ljava/lang/Number;

    .line 363
    .line 364
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 365
    .line 366
    .line 367
    move-result v0

    .line 368
    invoke-static {v0}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 373
    .line 374
    .line 375
    goto :goto_7

    .line 376
    :cond_e
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 377
    .line 378
    :cond_f
    return-object p1

    .line 379
    :pswitch_7
    check-cast p1, Ljava/util/List;

    .line 380
    .line 381
    if-eqz p1, :cond_10

    .line 382
    .line 383
    check-cast p1, Ljava/lang/Iterable;

    .line 384
    .line 385
    new-instance p0, Ljava/util/ArrayList;

    .line 386
    .line 387
    const/16 v0, 0xa

    .line 388
    .line 389
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 390
    .line 391
    .line 392
    move-result v0

    .line 393
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 394
    .line 395
    .line 396
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 397
    .line 398
    .line 399
    move-result-object p1

    .line 400
    :goto_8
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 401
    .line 402
    .line 403
    move-result v0

    .line 404
    if-eqz v0, :cond_11

    .line 405
    .line 406
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    check-cast v0, Ljava/lang/Boolean;

    .line 411
    .line 412
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 413
    .line 414
    .line 415
    move-result v0

    .line 416
    invoke-static {v0}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;

    .line 417
    .line 418
    .line 419
    move-result-object v0

    .line 420
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 421
    .line 422
    .line 423
    goto :goto_8

    .line 424
    :cond_10
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 425
    .line 426
    :cond_11
    return-object p0

    .line 427
    :pswitch_8
    check-cast p1, [Z

    .line 428
    .line 429
    if-eqz p1, :cond_12

    .line 430
    .line 431
    invoke-static {p1}, Lmx0/n;->c0([Z)Ljava/util/List;

    .line 432
    .line 433
    .line 434
    move-result-object p0

    .line 435
    check-cast p0, Ljava/lang/Iterable;

    .line 436
    .line 437
    new-instance p1, Ljava/util/ArrayList;

    .line 438
    .line 439
    const/16 v0, 0xa

    .line 440
    .line 441
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 442
    .line 443
    .line 444
    move-result v0

    .line 445
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 446
    .line 447
    .line 448
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 449
    .line 450
    .line 451
    move-result-object p0

    .line 452
    :goto_9
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 453
    .line 454
    .line 455
    move-result v0

    .line 456
    if-eqz v0, :cond_13

    .line 457
    .line 458
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    move-result-object v0

    .line 462
    check-cast v0, Ljava/lang/Boolean;

    .line 463
    .line 464
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 465
    .line 466
    .line 467
    move-result v0

    .line 468
    invoke-static {v0}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;

    .line 469
    .line 470
    .line 471
    move-result-object v0

    .line 472
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    goto :goto_9

    .line 476
    :cond_12
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 477
    .line 478
    :cond_13
    return-object p1

    .line 479
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

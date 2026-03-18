.class public final synthetic Lvp/w1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvp/j2;


# direct methods
.method public synthetic constructor <init>(Lvp/j2;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvp/w1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvp/w1;->e:Lvp/j2;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 14

    .line 1
    iget v0, p0, Lvp/w1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/w1;->e:Lvp/j2;

    .line 7
    .line 8
    invoke-virtual {p0}, Lvp/j2;->x0()V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Lvp/w1;->e:Lvp/j2;

    .line 13
    .line 14
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lvp/g1;

    .line 20
    .line 21
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 22
    .line 23
    iget-object v2, v0, Lvp/g1;->i:Lvp/p0;

    .line 24
    .line 25
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 26
    .line 27
    .line 28
    iget-object v3, v1, Lvp/w0;->x:Lvp/v0;

    .line 29
    .line 30
    invoke-virtual {v3}, Lvp/v0;->a()Z

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-nez v4, :cond_2

    .line 35
    .line 36
    iget-object v1, v1, Lvp/w0;->y:La8/s1;

    .line 37
    .line 38
    invoke-virtual {v1}, La8/s1;->g()J

    .line 39
    .line 40
    .line 41
    move-result-wide v4

    .line 42
    const-wide/16 v6, 0x1

    .line 43
    .line 44
    add-long/2addr v6, v4

    .line 45
    invoke-virtual {v1, v6, v7}, La8/s1;->h(J)V

    .line 46
    .line 47
    .line 48
    const-wide/16 v6, 0x5

    .line 49
    .line 50
    cmp-long v1, v4, v6

    .line 51
    .line 52
    if-ltz v1, :cond_0

    .line 53
    .line 54
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, v2, Lvp/p0;->m:Lvp/n0;

    .line 58
    .line 59
    const-string v0, "Permanently failed to retrieve Deferred Deep Link. Reached maximum retries."

    .line 60
    .line 61
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x1

    .line 65
    invoke-virtual {v3, p0}, Lvp/v0;->b(Z)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    iget-object v1, p0, Lvp/j2;->x:Lvp/x1;

    .line 70
    .line 71
    if-nez v1, :cond_1

    .line 72
    .line 73
    new-instance v1, Lvp/x1;

    .line 74
    .line 75
    const/4 v2, 0x3

    .line 76
    invoke-direct {v1, p0, v0, v2}, Lvp/x1;-><init>(Lvp/j2;Lvp/o1;I)V

    .line 77
    .line 78
    .line 79
    iput-object v1, p0, Lvp/j2;->x:Lvp/x1;

    .line 80
    .line 81
    :cond_1
    iget-object p0, p0, Lvp/j2;->x:Lvp/x1;

    .line 82
    .line 83
    const-wide/16 v0, 0x0

    .line 84
    .line 85
    invoke-virtual {p0, v0, v1}, Lvp/o;->b(J)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_2
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 90
    .line 91
    .line 92
    iget-object p0, v2, Lvp/p0;->q:Lvp/n0;

    .line 93
    .line 94
    const-string v0, "Deferred Deep Link already retrieved. Not fetching again."

    .line 95
    .line 96
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    :goto_0
    return-void

    .line 100
    :pswitch_1
    iget-object p0, p0, Lvp/w1;->e:Lvp/j2;

    .line 101
    .line 102
    iget-object p0, p0, Lvp/j2;->v:Lro/f;

    .line 103
    .line 104
    iget-object v0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v0, Lvp/g1;

    .line 107
    .line 108
    iget-object v1, v0, Lvp/g1;->j:Lvp/e1;

    .line 109
    .line 110
    iget-object v2, v0, Lvp/g1;->p:Lvp/j2;

    .line 111
    .line 112
    iget-object v3, v0, Lvp/g1;->h:Lvp/w0;

    .line 113
    .line 114
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1}, Lvp/e1;->a0()V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p0}, Lro/f;->v()Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    if-nez v1, :cond_3

    .line 125
    .line 126
    goto/16 :goto_5

    .line 127
    .line 128
    :cond_3
    invoke-virtual {p0}, Lro/f;->u()Z

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    const-string v1, "_cc"

    .line 133
    .line 134
    const/4 v4, 0x0

    .line 135
    if-eqz p0, :cond_4

    .line 136
    .line 137
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 138
    .line 139
    .line 140
    iget-object p0, v3, Lvp/w0;->A:La8/b;

    .line 141
    .line 142
    invoke-virtual {p0, v4}, La8/b;->u(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    new-instance p0, Landroid/os/Bundle;

    .line 146
    .line 147
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 148
    .line 149
    .line 150
    const-string v0, "source"

    .line 151
    .line 152
    const-string v4, "(not set)"

    .line 153
    .line 154
    invoke-virtual {p0, v0, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    const-string v0, "medium"

    .line 158
    .line 159
    invoke-virtual {p0, v0, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    const-string v0, "_cis"

    .line 163
    .line 164
    const-string v4, "intent"

    .line 165
    .line 166
    invoke-virtual {p0, v0, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    const-wide/16 v4, 0x1

    .line 170
    .line 171
    invoke-virtual {p0, v1, v4, v5}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 172
    .line 173
    .line 174
    invoke-static {v2}, Lvp/g1;->i(Lvp/b0;)V

    .line 175
    .line 176
    .line 177
    const-string v0, "auto"

    .line 178
    .line 179
    const-string v1, "_cmpx"

    .line 180
    .line 181
    invoke-virtual {v2, v0, v1, p0}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 182
    .line 183
    .line 184
    goto/16 :goto_4

    .line 185
    .line 186
    :cond_4
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 187
    .line 188
    .line 189
    iget-object p0, v3, Lvp/w0;->A:La8/b;

    .line 190
    .line 191
    invoke-virtual {p0}, La8/b;->t()Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object v5

    .line 195
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 196
    .line 197
    .line 198
    move-result v6

    .line 199
    if-eqz v6, :cond_5

    .line 200
    .line 201
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 202
    .line 203
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 204
    .line 205
    .line 206
    iget-object v0, v0, Lvp/p0;->k:Lvp/n0;

    .line 207
    .line 208
    const-string v1, "Cache still valid but referrer not found"

    .line 209
    .line 210
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_5
    iget-object v0, v3, Lvp/w0;->B:La8/s1;

    .line 215
    .line 216
    invoke-virtual {v0}, La8/s1;->g()J

    .line 217
    .line 218
    .line 219
    move-result-wide v6

    .line 220
    const-wide/32 v8, 0x36ee80

    .line 221
    .line 222
    .line 223
    div-long/2addr v6, v8

    .line 224
    invoke-static {v5}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    new-instance v5, Landroid/os/Bundle;

    .line 229
    .line 230
    invoke-direct {v5}, Landroid/os/Bundle;-><init>()V

    .line 231
    .line 232
    .line 233
    new-instance v10, Landroid/util/Pair;

    .line 234
    .line 235
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v11

    .line 239
    invoke-direct {v10, v11, v5}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v0}, Landroid/net/Uri;->getQueryParameterNames()Ljava/util/Set;

    .line 243
    .line 244
    .line 245
    move-result-object v11

    .line 246
    invoke-interface {v11}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 247
    .line 248
    .line 249
    move-result-object v11

    .line 250
    :goto_1
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 251
    .line 252
    .line 253
    move-result v12

    .line 254
    if-eqz v12, :cond_6

    .line 255
    .line 256
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v12

    .line 260
    check-cast v12, Ljava/lang/String;

    .line 261
    .line 262
    invoke-virtual {v0, v12}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v13

    .line 266
    invoke-virtual {v5, v12, v13}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    goto :goto_1

    .line 270
    :cond_6
    const-wide/16 v11, -0x1

    .line 271
    .line 272
    add-long/2addr v6, v11

    .line 273
    mul-long/2addr v6, v8

    .line 274
    iget-object v0, v10, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v0, Landroid/os/Bundle;

    .line 277
    .line 278
    invoke-virtual {v0, v1, v6, v7}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 279
    .line 280
    .line 281
    iget-object v0, v10, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 282
    .line 283
    if-nez v0, :cond_7

    .line 284
    .line 285
    const-string v0, "app"

    .line 286
    .line 287
    goto :goto_2

    .line 288
    :cond_7
    check-cast v0, Ljava/lang/String;

    .line 289
    .line 290
    :goto_2
    invoke-static {v2}, Lvp/g1;->i(Lvp/b0;)V

    .line 291
    .line 292
    .line 293
    iget-object v1, v10, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast v1, Landroid/os/Bundle;

    .line 296
    .line 297
    const-string v5, "_cmp"

    .line 298
    .line 299
    invoke-virtual {v2, v0, v5, v1}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 300
    .line 301
    .line 302
    :goto_3
    invoke-virtual {p0, v4}, La8/b;->u(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    :goto_4
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 306
    .line 307
    .line 308
    iget-object p0, v3, Lvp/w0;->B:La8/s1;

    .line 309
    .line 310
    const-wide/16 v0, 0x0

    .line 311
    .line 312
    invoke-virtual {p0, v0, v1}, La8/s1;->h(J)V

    .line 313
    .line 314
    .line 315
    :goto_5
    return-void

    .line 316
    :pswitch_2
    iget-object p0, p0, Lvp/w1;->e:Lvp/j2;

    .line 317
    .line 318
    invoke-virtual {p0}, Lvp/j2;->x0()V

    .line 319
    .line 320
    .line 321
    return-void

    .line 322
    nop

    .line 323
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

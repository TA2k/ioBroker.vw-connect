.class public final Lgc/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Z

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lgc/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lgc/a;->g:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lgc/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    check-cast p2, Landroidx/lifecycle/q;

    .line 13
    .line 14
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 15
    .line 16
    new-instance v0, Lgc/a;

    .line 17
    .line 18
    iget-object p0, p0, Lgc/a;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 21
    .line 22
    const/4 v1, 0x3

    .line 23
    invoke-direct {v0, p0, p3, v1}, Lgc/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    iput-boolean p1, v0, Lgc/a;->e:Z

    .line 27
    .line 28
    iput-object p2, v0, Lgc/a;->f:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Lgc/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    check-cast p2, Lmi/c;

    .line 43
    .line 44
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    new-instance v0, Lgc/a;

    .line 47
    .line 48
    iget-object p0, p0, Lgc/a;->g:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Loi/c;

    .line 51
    .line 52
    const/4 v1, 0x2

    .line 53
    invoke-direct {v0, p0, p3, v1}, Lgc/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    iput-boolean p1, v0, Lgc/a;->e:Z

    .line 57
    .line 58
    iput-object p2, v0, Lgc/a;->f:Ljava/lang/Object;

    .line 59
    .line 60
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    invoke-virtual {v0, p0}, Lgc/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_1
    check-cast p1, Lss0/d0;

    .line 68
    .line 69
    check-cast p2, Ljava/lang/Boolean;

    .line 70
    .line 71
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    new-instance v0, Lgc/a;

    .line 78
    .line 79
    iget-object p0, p0, Lgc/a;->g:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Lmy/t;

    .line 82
    .line 83
    const/4 v1, 0x1

    .line 84
    invoke-direct {v0, p0, p3, v1}, Lgc/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 85
    .line 86
    .line 87
    check-cast p1, Lss0/d0;

    .line 88
    .line 89
    iput-object p1, v0, Lgc/a;->f:Ljava/lang/Object;

    .line 90
    .line 91
    iput-boolean p2, v0, Lgc/a;->e:Z

    .line 92
    .line 93
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    invoke-virtual {v0, p0}, Lgc/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    return-object p0

    .line 99
    :pswitch_2
    check-cast p1, Ltb/t;

    .line 100
    .line 101
    check-cast p2, Ljava/lang/Boolean;

    .line 102
    .line 103
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 108
    .line 109
    new-instance v0, Lgc/a;

    .line 110
    .line 111
    iget-object p0, p0, Lgc/a;->g:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast p0, Lgc/b;

    .line 114
    .line 115
    const/4 v1, 0x0

    .line 116
    invoke-direct {v0, p0, p3, v1}, Lgc/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 117
    .line 118
    .line 119
    iput-object p1, v0, Lgc/a;->f:Ljava/lang/Object;

    .line 120
    .line 121
    iput-boolean p2, v0, Lgc/a;->e:Z

    .line 122
    .line 123
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    invoke-virtual {v0, p0}, Lgc/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lgc/a;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v4, p0, Lgc/a;->g:Ljava/lang/Object;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    iget-boolean v0, p0, Lgc/a;->e:Z

    .line 13
    .line 14
    iget-object p0, p0, Lgc/a;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Landroidx/lifecycle/q;

    .line 17
    .line 18
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    check-cast v4, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 24
    .line 25
    invoke-virtual {v4, v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->updateRPALifecycle(ZLandroidx/lifecycle/q;)V

    .line 26
    .line 27
    .line 28
    return-object v3

    .line 29
    :pswitch_0
    iget-boolean v0, p0, Lgc/a;->e:Z

    .line 30
    .line 31
    iget-object p0, p0, Lgc/a;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lmi/c;

    .line 34
    .line 35
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    check-cast v4, Loi/c;

    .line 41
    .line 42
    if-nez p0, :cond_0

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_0
    iget-object p1, v4, Loi/c;->d:Loi/b;

    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_2

    .line 52
    .line 53
    if-ne p1, v1, :cond_1

    .line 54
    .line 55
    iget-object p0, p0, Lmi/c;->a:Lmi/f;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    new-instance p0, La8/r0;

    .line 59
    .line 60
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_2
    iget-object p0, p0, Lmi/c;->b:Lmi/f;

    .line 65
    .line 66
    :goto_0
    if-eqz v0, :cond_3

    .line 67
    .line 68
    iget-object p1, p0, Lmi/f;->c:Ljava/lang/String;

    .line 69
    .line 70
    if-nez p1, :cond_4

    .line 71
    .line 72
    iget-object p1, p0, Lmi/f;->b:Ljava/lang/String;

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    iget-object p1, p0, Lmi/f;->b:Ljava/lang/String;

    .line 76
    .line 77
    :cond_4
    :goto_1
    new-instance v2, Loi/d;

    .line 78
    .line 79
    iget-object p0, p0, Lmi/f;->a:Ljava/lang/String;

    .line 80
    .line 81
    invoke-direct {v2, p0, p1}, Loi/d;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    :goto_2
    return-object v2

    .line 85
    :pswitch_1
    iget-object v0, p0, Lgc/a;->f:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v0, Lss0/d0;

    .line 88
    .line 89
    check-cast v0, Lss0/d0;

    .line 90
    .line 91
    iget-boolean p0, p0, Lgc/a;->e:Z

    .line 92
    .line 93
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 94
    .line 95
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    sget-object v1, Lmy/j;->d:Lmy/j;

    .line 103
    .line 104
    invoke-virtual {p1, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    sget-object v1, Lmy/j;->e:Lmy/j;

    .line 108
    .line 109
    invoke-virtual {p1, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    if-eqz v0, :cond_5

    .line 113
    .line 114
    instance-of v1, v0, Lss0/j0;

    .line 115
    .line 116
    if-eqz v1, :cond_6

    .line 117
    .line 118
    :cond_5
    sget-object v1, Lmy/j;->f:Lmy/j;

    .line 119
    .line 120
    invoke-virtual {p1, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    :cond_6
    instance-of v0, v0, Lss0/g;

    .line 124
    .line 125
    if-eqz v0, :cond_7

    .line 126
    .line 127
    sget-object v0, Lmy/j;->g:Lmy/j;

    .line 128
    .line 129
    invoke-virtual {p1, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    :cond_7
    sget-object v0, Lmy/j;->h:Lmy/j;

    .line 133
    .line 134
    invoke-virtual {p1, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    if-eqz p0, :cond_8

    .line 138
    .line 139
    sget-object p0, Lmy/j;->j:Lmy/j;

    .line 140
    .line 141
    invoke-virtual {p1, p0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_8
    sget-object p0, Lmy/j;->i:Lmy/j;

    .line 146
    .line 147
    invoke-virtual {p1, p0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    :goto_3
    invoke-static {p1}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 151
    .line 152
    .line 153
    move-result-object v12

    .line 154
    check-cast v4, Lmy/t;

    .line 155
    .line 156
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    move-object v5, p0

    .line 161
    check-cast v5, Lmy/p;

    .line 162
    .line 163
    const/4 v11, 0x0

    .line 164
    const/16 v13, 0x3f

    .line 165
    .line 166
    const/4 v6, 0x0

    .line 167
    const/4 v7, 0x0

    .line 168
    const/4 v8, 0x0

    .line 169
    const/4 v9, 0x0

    .line 170
    const/4 v10, 0x0

    .line 171
    invoke-static/range {v5 .. v13}, Lmy/p;->a(Lmy/p;Ljava/lang/String;Lmy/m;Lmy/o;Lmy/l;Lmy/k;ZLnx0/c;I)Lmy/p;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 176
    .line 177
    .line 178
    return-object v3

    .line 179
    :pswitch_2
    iget-object v0, p0, Lgc/a;->f:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast v0, Ltb/t;

    .line 182
    .line 183
    iget-boolean p0, p0, Lgc/a;->e:Z

    .line 184
    .line 185
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 186
    .line 187
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    iget-object p1, v0, Ltb/t;->a:Ltb/s;

    .line 191
    .line 192
    sget-object v3, Ltb/s;->e:Ltb/s;

    .line 193
    .line 194
    const/4 v4, 0x0

    .line 195
    if-eq p1, v3, :cond_a

    .line 196
    .line 197
    sget-object v3, Ltb/s;->f:Ltb/s;

    .line 198
    .line 199
    if-ne p1, v3, :cond_9

    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_9
    move p1, v4

    .line 203
    goto :goto_5

    .line 204
    :cond_a
    :goto_4
    move p1, v1

    .line 205
    :goto_5
    const-class v3, Lgc/b;

    .line 206
    .line 207
    const-string v5, "Kt"

    .line 208
    .line 209
    const/16 v6, 0x2e

    .line 210
    .line 211
    const/16 v7, 0x24

    .line 212
    .line 213
    if-eqz p1, :cond_c

    .line 214
    .line 215
    sget-object v8, Lgi/b;->g:Lgi/b;

    .line 216
    .line 217
    new-instance v9, Lfl/c;

    .line 218
    .line 219
    const/4 v10, 0x2

    .line 220
    invoke-direct {v9, v0, v10}, Lfl/c;-><init>(Ltb/t;I)V

    .line 221
    .line 222
    .line 223
    sget-object v0, Lgi/a;->e:Lgi/a;

    .line 224
    .line 225
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v10

    .line 229
    invoke-static {v10, v7}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v11

    .line 233
    invoke-static {v6, v11, v11}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v11

    .line 237
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 238
    .line 239
    .line 240
    move-result v12

    .line 241
    if-nez v12, :cond_b

    .line 242
    .line 243
    goto :goto_6

    .line 244
    :cond_b
    invoke-static {v11, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object v10

    .line 248
    :goto_6
    invoke-static {v10, v0, v8, v2, v9}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 249
    .line 250
    .line 251
    :cond_c
    if-eqz p0, :cond_e

    .line 252
    .line 253
    sget-object v0, Lgi/b;->g:Lgi/b;

    .line 254
    .line 255
    new-instance v8, Lg4/a0;

    .line 256
    .line 257
    const/16 v9, 0x12

    .line 258
    .line 259
    invoke-direct {v8, v9}, Lg4/a0;-><init>(I)V

    .line 260
    .line 261
    .line 262
    sget-object v9, Lgi/a;->e:Lgi/a;

    .line 263
    .line 264
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object v3

    .line 268
    invoke-static {v3, v7}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v7

    .line 272
    invoke-static {v6, v7, v7}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 273
    .line 274
    .line 275
    move-result-object v6

    .line 276
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 277
    .line 278
    .line 279
    move-result v7

    .line 280
    if-nez v7, :cond_d

    .line 281
    .line 282
    goto :goto_7

    .line 283
    :cond_d
    invoke-static {v6, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    :goto_7
    invoke-static {v3, v9, v0, v2, v8}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 288
    .line 289
    .line 290
    :cond_e
    if-nez p1, :cond_10

    .line 291
    .line 292
    if-eqz p0, :cond_f

    .line 293
    .line 294
    goto :goto_8

    .line 295
    :cond_f
    move v1, v4

    .line 296
    :cond_10
    :goto_8
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    return-object p0

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

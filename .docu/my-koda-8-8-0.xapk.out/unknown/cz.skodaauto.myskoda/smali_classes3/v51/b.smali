.class public final Lv51/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lv51/f;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lv51/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lv51/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lv51/b;->e:Lv51/f;

    .line 4
    .line 5
    iput-object p2, p0, Lv51/b;->f:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lv51/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lv51/b;

    .line 7
    .line 8
    iget-object v0, p0, Lv51/b;->f:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lv51/b;->e:Lv51/f;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lv51/b;-><init>(Lv51/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lv51/b;

    .line 18
    .line 19
    iget-object v0, p0, Lv51/b;->f:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lv51/b;->e:Lv51/f;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lv51/b;-><init>(Lv51/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lv51/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lv51/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lv51/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lv51/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lv51/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lv51/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lv51/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lv51/b;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lv51/b;->f:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lv51/b;->e:Lv51/f;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lv51/f;->a:Lca/d;

    .line 16
    .line 17
    new-instance p1, Lq51/e;

    .line 18
    .line 19
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v1, p1}, Lca/d;->c(Ljava/lang/String;Lq51/e;)Lkp/r8;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    instance-of p1, p0, Lg91/b;

    .line 27
    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    instance-of p1, p0, Lg91/a;

    .line 34
    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    check-cast p0, Lg91/a;

    .line 38
    .line 39
    iget-object p0, p0, Lg91/a;->a:Lq51/p;

    .line 40
    .line 41
    invoke-static {p0, v1}, Llp/xa;->d(Lq51/p;Ljava/lang/String;)Lg61/t;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    :goto_0
    new-instance p1, Llx0/o;

    .line 50
    .line 51
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-object p1

    .line 55
    :cond_1
    new-instance p0, La8/r0;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p0, Lv51/f;->a:Lca/d;

    .line 67
    .line 68
    new-instance p1, Lq51/e;

    .line 69
    .line 70
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 71
    .line 72
    .line 73
    const-string v0, "key"

    .line 74
    .line 75
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget-object v0, p0, Lca/d;->d:Landroid/content/Context;

    .line 79
    .line 80
    invoke-static {v0}, Lq51/r;->e(Landroid/content/Context;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-static {v0, v1, p1}, Lq51/r;->b(Ljava/lang/String;Ljava/lang/String;Lq51/e;)Lq51/d;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    if-nez v0, :cond_2

    .line 89
    .line 90
    new-instance p0, Lg91/b;

    .line 91
    .line 92
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 93
    .line 94
    invoke-direct {p0, p1}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    goto/16 :goto_3

    .line 98
    .line 99
    :cond_2
    invoke-virtual {v0}, Lq51/d;->a()Lkp/r8;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    instance-of v2, v0, Lg91/b;

    .line 104
    .line 105
    if-eqz v2, :cond_8

    .line 106
    .line 107
    new-instance v2, Lg91/b;

    .line 108
    .line 109
    check-cast v0, Lg91/b;

    .line 110
    .line 111
    iget-object v0, v0, Lg91/b;->a:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    if-eqz v0, :cond_7

    .line 120
    .line 121
    invoke-virtual {p0, v1, p1}, Lca/d;->b(Ljava/lang/String;Lq51/e;)Lkp/r8;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    instance-of v0, p0, Lg91/b;

    .line 126
    .line 127
    if-eqz v0, :cond_5

    .line 128
    .line 129
    check-cast p0, Lg91/b;

    .line 130
    .line 131
    iget-object p0, p0, Lg91/b;->a:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast p0, Lq51/a;

    .line 134
    .line 135
    if-eqz p0, :cond_7

    .line 136
    .line 137
    invoke-static {}, Lq51/r;->a()Lkp/r8;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    instance-of v3, v0, Lg91/b;

    .line 142
    .line 143
    if-eqz v3, :cond_3

    .line 144
    .line 145
    check-cast v0, Lg91/b;

    .line 146
    .line 147
    iget-object v0, v0, Lg91/b;->a:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v0, Lq51/b;

    .line 150
    .line 151
    iget-wide v3, p0, Lq51/a;->a:J

    .line 152
    .line 153
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    invoke-static {p1}, Lq51/r;->c(Lq51/e;)V

    .line 157
    .line 158
    .line 159
    new-instance p0, Ljava/lang/StringBuilder;

    .line 160
    .line 161
    const-string p1, "technology.cariad.cat.keychain.a_"

    .line 162
    .line 163
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p0, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    iget-object p1, v0, Lq51/b;->a:Ljava/security/KeyStore;

    .line 174
    .line 175
    invoke-static {p0, p1}, Lq51/r;->d(Ljava/lang/String;Ljava/security/KeyStore;)Lkp/r8;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    instance-of p1, p0, Lg91/b;

    .line 180
    .line 181
    if-eqz p1, :cond_7

    .line 182
    .line 183
    check-cast p0, Lg91/b;

    .line 184
    .line 185
    iget-object p0, p0, Lg91/b;->a:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p0, Ljavax/crypto/SecretKey;

    .line 188
    .line 189
    if-eqz p0, :cond_7

    .line 190
    .line 191
    invoke-interface {p0}, Ljavax/security/auth/Destroyable;->isDestroyed()Z

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    if-nez p0, :cond_7

    .line 196
    .line 197
    const/4 p0, 0x1

    .line 198
    goto :goto_2

    .line 199
    :cond_3
    instance-of p0, v0, Lg91/a;

    .line 200
    .line 201
    if-eqz p0, :cond_4

    .line 202
    .line 203
    goto :goto_1

    .line 204
    :cond_4
    new-instance p0, La8/r0;

    .line 205
    .line 206
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 207
    .line 208
    .line 209
    throw p0

    .line 210
    :cond_5
    instance-of p0, p0, Lg91/a;

    .line 211
    .line 212
    if-eqz p0, :cond_6

    .line 213
    .line 214
    goto :goto_1

    .line 215
    :cond_6
    new-instance p0, La8/r0;

    .line 216
    .line 217
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 218
    .line 219
    .line 220
    throw p0

    .line 221
    :cond_7
    :goto_1
    const/4 p0, 0x0

    .line 222
    :goto_2
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    invoke-direct {v2, p0}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    move-object p0, v2

    .line 230
    goto :goto_3

    .line 231
    :cond_8
    instance-of p0, v0, Lg91/a;

    .line 232
    .line 233
    if-eqz p0, :cond_b

    .line 234
    .line 235
    move-object p0, v0

    .line 236
    :goto_3
    instance-of p1, p0, Lg91/b;

    .line 237
    .line 238
    if-eqz p1, :cond_9

    .line 239
    .line 240
    check-cast p0, Lg91/b;

    .line 241
    .line 242
    iget-object p0, p0, Lg91/b;->a:Ljava/lang/Object;

    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_9
    instance-of p1, p0, Lg91/a;

    .line 246
    .line 247
    if-eqz p1, :cond_a

    .line 248
    .line 249
    check-cast p0, Lg91/a;

    .line 250
    .line 251
    iget-object p0, p0, Lg91/a;->a:Lq51/p;

    .line 252
    .line 253
    invoke-static {p0, v1}, Llp/xa;->d(Lq51/p;Ljava/lang/String;)Lg61/t;

    .line 254
    .line 255
    .line 256
    move-result-object p0

    .line 257
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 258
    .line 259
    .line 260
    move-result-object p0

    .line 261
    :goto_4
    new-instance p1, Llx0/o;

    .line 262
    .line 263
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    return-object p1

    .line 267
    :cond_a
    new-instance p0, La8/r0;

    .line 268
    .line 269
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 270
    .line 271
    .line 272
    throw p0

    .line 273
    :cond_b
    new-instance p0, La8/r0;

    .line 274
    .line 275
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 276
    .line 277
    .line 278
    throw p0

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

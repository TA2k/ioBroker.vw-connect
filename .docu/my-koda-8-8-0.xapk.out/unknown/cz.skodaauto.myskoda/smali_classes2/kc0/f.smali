.class public final Lkc0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lic0/a;

.field public final b:Lkc0/g;

.field public final c:Lbd0/c;

.field public final d:Lam0/c;


# direct methods
.method public constructor <init>(Lic0/a;Lkc0/g;Lbd0/c;Lam0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/f;->a:Lic0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lkc0/f;->b:Lkc0/g;

    .line 7
    .line 8
    iput-object p3, p0, Lkc0/f;->c:Lbd0/c;

    .line 9
    .line 10
    iput-object p4, p0, Lkc0/f;->d:Lam0/c;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lkc0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p1, Lkc0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkc0/d;

    .line 7
    .line 8
    iget v1, v0, Lkc0/d;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lkc0/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkc0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkc0/d;-><init>(Lkc0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkc0/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkc0/d;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    .line 44
    goto :goto_4

    .line 45
    :catchall_0
    move-exception v0

    .line 46
    move-object p0, v0

    .line 47
    goto :goto_5

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iput v5, v0, Lkc0/d;->f:I

    .line 64
    .line 65
    iget-object p1, p0, Lkc0/f;->d:Lam0/c;

    .line 66
    .line 67
    invoke-virtual {p1, v3, v0}, Lam0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    if-ne p1, v1, :cond_4

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_4
    :goto_1
    check-cast p1, Lcm0/b;

    .line 75
    .line 76
    iget-object v2, p0, Lkc0/f;->b:Lkc0/g;

    .line 77
    .line 78
    check-cast v2, Lic0/p;

    .line 79
    .line 80
    iget-object v2, v2, Lic0/p;->f:Lyy0/c2;

    .line 81
    .line 82
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    check-cast v2, Llc0/d;

    .line 87
    .line 88
    if-eqz v2, :cond_5

    .line 89
    .line 90
    iget-object v2, v2, Llc0/d;->a:Ljava/lang/String;

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_5
    const/4 v2, 0x0

    .line 94
    :goto_2
    if-eqz v2, :cond_9

    .line 95
    .line 96
    :try_start_1
    iput v4, v0, Lkc0/d;->f:I

    .line 97
    .line 98
    invoke-virtual {p0, p1, v2, v0}, Lkc0/f;->c(Lcm0/b;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    if-ne p1, v1, :cond_6

    .line 103
    .line 104
    :goto_3
    return-object v1

    .line 105
    :cond_6
    :goto_4
    check-cast p1, Lne0/t;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 106
    .line 107
    goto :goto_6

    .line 108
    :goto_5
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    :goto_6
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    if-nez v5, :cond_8

    .line 117
    .line 118
    check-cast p1, Lne0/t;

    .line 119
    .line 120
    if-nez p1, :cond_7

    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_7
    new-instance p0, Lne0/e;

    .line 124
    .line 125
    invoke-direct {p0, v3}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    return-object p0

    .line 129
    :cond_8
    new-instance v4, Lne0/c;

    .line 130
    .line 131
    const/4 v8, 0x0

    .line 132
    const/16 v9, 0x1e

    .line 133
    .line 134
    const/4 v6, 0x0

    .line 135
    const/4 v7, 0x0

    .line 136
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 137
    .line 138
    .line 139
    return-object v4

    .line 140
    :cond_9
    :goto_7
    new-instance v5, Lne0/c;

    .line 141
    .line 142
    new-instance v6, Ljava/lang/Exception;

    .line 143
    .line 144
    const-string p0, "Connect token not available"

    .line 145
    .line 146
    invoke-direct {v6, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    const/4 v9, 0x0

    .line 150
    const/16 v10, 0x1e

    .line 151
    .line 152
    const/4 v7, 0x0

    .line 153
    const/4 v8, 0x0

    .line 154
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 155
    .line 156
    .line 157
    return-object v5
.end method

.method public final c(Lcm0/b;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p3, Lkc0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lkc0/e;

    .line 7
    .line 8
    iget v1, v0, Lkc0/e;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lkc0/e;->f:I

    .line 18
    .line 19
    :goto_0
    move-object p3, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lkc0/e;

    .line 22
    .line 23
    invoke-direct {v0, p0, p3}, Lkc0/e;-><init>(Lkc0/f;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, p3, Lkc0/e;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, p3, Lkc0/e;->f:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto/16 :goto_7

    .line 42
    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object v0, p0, Lkc0/f;->a:Lic0/a;

    .line 55
    .line 56
    iget-object v2, v0, Lic0/a;->f:Ljava/util/EnumMap;

    .line 57
    .line 58
    iget-object v4, v0, Lic0/a;->e:Ljava/util/EnumMap;

    .line 59
    .line 60
    const-string v5, "environment"

    .line 61
    .line 62
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    const-string v5, "$v$c$cz-skodaauto-myskoda-library-authcomponent-model-IdToken$-idToken$0"

    .line 66
    .line 67
    invoke-static {p2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    :try_start_0
    sget-object v5, Llc0/l;->e:Llc0/l;

    .line 71
    .line 72
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 73
    .line 74
    .line 75
    move-result-object v6

    .line 76
    invoke-virtual {v6}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    invoke-interface {v4, v5, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 84
    .line 85
    .line 86
    move-result-object v6

    .line 87
    invoke-virtual {v6}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    invoke-interface {v2, v5, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    new-instance v6, Ld01/z;

    .line 95
    .line 96
    const/4 v7, 0x0

    .line 97
    invoke-direct {v6, v7}, Ld01/z;-><init>(I)V

    .line 98
    .line 99
    .line 100
    const-string v7, "https"

    .line 101
    .line 102
    invoke-virtual {v6, v7}, Ld01/z;->k(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    iget-object v0, v0, Lic0/a;->d:Lxl0/g;

    .line 106
    .line 107
    invoke-interface {v0, p1}, Lxl0/g;->a(Lcm0/b;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-virtual {v6, v0}, Ld01/z;->f(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v6}, Ld01/z;->e()V

    .line 115
    .line 116
    .line 117
    const-string v0, "client_id"

    .line 118
    .line 119
    invoke-static {v5, p1}, Lic0/a;->a(Llc0/l;Lcm0/b;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    invoke-virtual {v6, v0, p1}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const-string p1, "nonce"

    .line 127
    .line 128
    invoke-virtual {v2, v5}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    check-cast v0, Ljava/lang/String;

    .line 133
    .line 134
    invoke-virtual {v6, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    const-string p1, "redirect_uri"

    .line 138
    .line 139
    const-string v0, "myskoda://redirect/login/"

    .line 140
    .line 141
    invoke-virtual {v6, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    const-string p1, "response_type"

    .line 145
    .line 146
    const-string v0, "code"

    .line 147
    .line 148
    invoke-virtual {v6, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    const-string p1, "scope"

    .line 152
    .line 153
    const-string v0, "openid"

    .line 154
    .line 155
    invoke-virtual {v6, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    const-string p1, "state"

    .line 159
    .line 160
    invoke-virtual {v4, v5}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    check-cast v0, Ljava/lang/String;

    .line 165
    .line 166
    invoke-virtual {v6, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    const-string p1, "prompt"

    .line 170
    .line 171
    const-string v0, "none"

    .line 172
    .line 173
    invoke-virtual {v6, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    const-string p1, "id_token_hint"

    .line 177
    .line 178
    invoke-virtual {v6, p1, p2}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v6}, Ld01/z;->c()Ld01/a0;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    invoke-virtual {p1}, Ld01/a0;->k()Ljava/net/URL;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    new-instance p2, Lne0/e;

    .line 190
    .line 191
    invoke-direct {p2, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 192
    .line 193
    .line 194
    goto :goto_2

    .line 195
    :catch_0
    move-exception v0

    .line 196
    move-object p1, v0

    .line 197
    move-object v5, p1

    .line 198
    new-instance v4, Lne0/c;

    .line 199
    .line 200
    const/4 v8, 0x0

    .line 201
    const/16 v9, 0x1e

    .line 202
    .line 203
    const/4 v6, 0x0

    .line 204
    const/4 v7, 0x0

    .line 205
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 206
    .line 207
    .line 208
    move-object p2, v4

    .line 209
    :goto_2
    instance-of p1, p2, Lne0/e;

    .line 210
    .line 211
    if-eqz p1, :cond_9

    .line 212
    .line 213
    check-cast p2, Lne0/e;

    .line 214
    .line 215
    iget-object p1, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast p1, Ljava/net/URL;

    .line 218
    .line 219
    invoke-virtual {p1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    const-string p2, "toString(...)"

    .line 224
    .line 225
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    const/16 p2, 0x10

    .line 229
    .line 230
    and-int/lit8 v0, p2, 0x2

    .line 231
    .line 232
    const/4 v2, 0x0

    .line 233
    if-eqz v0, :cond_3

    .line 234
    .line 235
    move v6, v3

    .line 236
    goto :goto_3

    .line 237
    :cond_3
    move v6, v2

    .line 238
    :goto_3
    and-int/lit8 v0, p2, 0x4

    .line 239
    .line 240
    if-eqz v0, :cond_4

    .line 241
    .line 242
    move v7, v3

    .line 243
    goto :goto_4

    .line 244
    :cond_4
    move v7, v2

    .line 245
    :goto_4
    and-int/lit8 v0, p2, 0x8

    .line 246
    .line 247
    if-eqz v0, :cond_5

    .line 248
    .line 249
    move v8, v2

    .line 250
    goto :goto_5

    .line 251
    :cond_5
    move v8, v3

    .line 252
    :goto_5
    and-int/2addr p2, p2

    .line 253
    if-eqz p2, :cond_6

    .line 254
    .line 255
    move v9, v2

    .line 256
    goto :goto_6

    .line 257
    :cond_6
    move v9, v3

    .line 258
    :goto_6
    iget-object p0, p0, Lkc0/f;->c:Lbd0/c;

    .line 259
    .line 260
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 261
    .line 262
    new-instance v5, Ljava/net/URL;

    .line 263
    .line 264
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    move-object v4, p0

    .line 268
    check-cast v4, Lzc0/b;

    .line 269
    .line 270
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    iput v3, p3, Lkc0/e;->f:I

    .line 275
    .line 276
    invoke-static {p0, p3}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v0

    .line 280
    if-ne v0, v1, :cond_7

    .line 281
    .line 282
    return-object v1

    .line 283
    :cond_7
    :goto_7
    check-cast v0, Lne0/t;

    .line 284
    .line 285
    instance-of p0, v0, Lne0/c;

    .line 286
    .line 287
    if-nez p0, :cond_8

    .line 288
    .line 289
    new-instance p0, Lne0/e;

    .line 290
    .line 291
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    return-object p0

    .line 297
    :cond_8
    check-cast v0, Lne0/c;

    .line 298
    .line 299
    iget-object p0, v0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 300
    .line 301
    throw p0

    .line 302
    :cond_9
    instance-of p0, p2, Lne0/c;

    .line 303
    .line 304
    if-eqz p0, :cond_a

    .line 305
    .line 306
    check-cast p2, Lne0/c;

    .line 307
    .line 308
    iget-object p0, p2, Lne0/c;->a:Ljava/lang/Throwable;

    .line 309
    .line 310
    throw p0

    .line 311
    :cond_a
    new-instance p0, La8/r0;

    .line 312
    .line 313
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 314
    .line 315
    .line 316
    throw p0
.end method

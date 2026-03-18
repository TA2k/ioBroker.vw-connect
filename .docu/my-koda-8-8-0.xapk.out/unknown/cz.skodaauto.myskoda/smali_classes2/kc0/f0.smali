.class public final Lkc0/f0;
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
    iput-object p1, p0, Lkc0/f0;->a:Lic0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lkc0/f0;->b:Lkc0/g;

    .line 7
    .line 8
    iput-object p3, p0, Lkc0/f0;->c:Lbd0/c;

    .line 9
    .line 10
    iput-object p4, p0, Lkc0/f0;->d:Lam0/c;

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
    invoke-virtual {p0, p2}, Lkc0/f0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lkc0/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkc0/d0;

    .line 7
    .line 8
    iget v1, v0, Lkc0/d0;->g:I

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
    iput v1, v0, Lkc0/d0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkc0/d0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkc0/d0;-><init>(Lkc0/f0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkc0/d0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkc0/d0;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lkc0/f0;->b:Lkc0/g;

    .line 32
    .line 33
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x2

    .line 37
    const/4 v7, 0x1

    .line 38
    if-eqz v2, :cond_4

    .line 39
    .line 40
    if-eq v2, v7, :cond_3

    .line 41
    .line 42
    if-eq v2, v6, :cond_2

    .line 43
    .line 44
    if-ne v2, v5, :cond_1

    .line 45
    .line 46
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    goto :goto_5

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    move-object p0, v0

    .line 52
    goto :goto_6

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    iget-object v2, v0, Lkc0/d0;->d:Lcm0/b;

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iput v7, v0, Lkc0/d0;->g:I

    .line 75
    .line 76
    iget-object p1, p0, Lkc0/f0;->d:Lam0/c;

    .line 77
    .line 78
    invoke-virtual {p1, v4, v0}, Lam0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-ne p1, v1, :cond_5

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_5
    :goto_1
    move-object v2, p1

    .line 86
    check-cast v2, Lcm0/b;

    .line 87
    .line 88
    move-object p1, v3

    .line 89
    check-cast p1, Lic0/p;

    .line 90
    .line 91
    invoke-virtual {p1}, Lic0/p;->b()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    iput-object v2, v0, Lkc0/d0;->d:Lcm0/b;

    .line 96
    .line 97
    iput v6, v0, Lkc0/d0;->g:I

    .line 98
    .line 99
    invoke-virtual {p1, v7, v0}, Lic0/p;->d(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    if-ne p1, v1, :cond_6

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_6
    :goto_2
    check-cast v3, Lic0/p;

    .line 107
    .line 108
    iget-object p1, v3, Lic0/p;->f:Lyy0/c2;

    .line 109
    .line 110
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    check-cast p1, Llc0/d;

    .line 115
    .line 116
    const/4 v3, 0x0

    .line 117
    if-eqz p1, :cond_7

    .line 118
    .line 119
    iget-object p1, p1, Llc0/d;->a:Ljava/lang/String;

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_7
    move-object p1, v3

    .line 123
    :goto_3
    if-eqz p1, :cond_b

    .line 124
    .line 125
    :try_start_1
    iput-object v3, v0, Lkc0/d0;->d:Lcm0/b;

    .line 126
    .line 127
    iput v5, v0, Lkc0/d0;->g:I

    .line 128
    .line 129
    invoke-virtual {p0, v2, p1, v0}, Lkc0/f0;->c(Lcm0/b;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, v1, :cond_8

    .line 134
    .line 135
    :goto_4
    return-object v1

    .line 136
    :cond_8
    :goto_5
    check-cast p1, Lne0/t;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 137
    .line 138
    goto :goto_7

    .line 139
    :goto_6
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    :goto_7
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 144
    .line 145
    .line 146
    move-result-object v6

    .line 147
    if-nez v6, :cond_a

    .line 148
    .line 149
    check-cast p1, Lne0/t;

    .line 150
    .line 151
    if-nez p1, :cond_9

    .line 152
    .line 153
    goto :goto_8

    .line 154
    :cond_9
    new-instance p0, Lne0/e;

    .line 155
    .line 156
    invoke-direct {p0, v4}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    return-object p0

    .line 160
    :cond_a
    new-instance v5, Lne0/c;

    .line 161
    .line 162
    const/4 v9, 0x0

    .line 163
    const/16 v10, 0x1e

    .line 164
    .line 165
    const/4 v7, 0x0

    .line 166
    const/4 v8, 0x0

    .line 167
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 168
    .line 169
    .line 170
    return-object v5

    .line 171
    :cond_b
    :goto_8
    new-instance v6, Lne0/c;

    .line 172
    .line 173
    new-instance v7, Ljava/lang/Exception;

    .line 174
    .line 175
    const-string p0, "Connect token not available"

    .line 176
    .line 177
    invoke-direct {v7, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    const/4 v10, 0x0

    .line 181
    const/16 v11, 0x1e

    .line 182
    .line 183
    const/4 v8, 0x0

    .line 184
    const/4 v9, 0x0

    .line 185
    invoke-direct/range {v6 .. v11}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 186
    .line 187
    .line 188
    return-object v6
.end method

.method public final c(Lcm0/b;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p3, Lkc0/e0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lkc0/e0;

    .line 7
    .line 8
    iget v1, v0, Lkc0/e0;->f:I

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
    iput v1, v0, Lkc0/e0;->f:I

    .line 18
    .line 19
    :goto_0
    move-object p3, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lkc0/e0;

    .line 22
    .line 23
    invoke-direct {v0, p0, p3}, Lkc0/e0;-><init>(Lkc0/f0;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, p3, Lkc0/e0;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, p3, Lkc0/e0;->f:I

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
    iget-object v0, p0, Lkc0/f0;->a:Lic0/a;

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
    const-string p1, "id_token_hint"

    .line 170
    .line 171
    invoke-virtual {v6, p1, p2}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v6}, Ld01/z;->c()Ld01/a0;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    invoke-virtual {p1}, Ld01/a0;->k()Ljava/net/URL;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    new-instance p2, Lne0/e;

    .line 183
    .line 184
    invoke-direct {p2, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 185
    .line 186
    .line 187
    goto :goto_2

    .line 188
    :catch_0
    move-exception v0

    .line 189
    move-object p1, v0

    .line 190
    move-object v5, p1

    .line 191
    new-instance v4, Lne0/c;

    .line 192
    .line 193
    const/4 v8, 0x0

    .line 194
    const/16 v9, 0x1e

    .line 195
    .line 196
    const/4 v6, 0x0

    .line 197
    const/4 v7, 0x0

    .line 198
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 199
    .line 200
    .line 201
    move-object p2, v4

    .line 202
    :goto_2
    instance-of p1, p2, Lne0/e;

    .line 203
    .line 204
    if-eqz p1, :cond_9

    .line 205
    .line 206
    check-cast p2, Lne0/e;

    .line 207
    .line 208
    iget-object p1, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast p1, Ljava/net/URL;

    .line 211
    .line 212
    invoke-virtual {p1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    const-string p2, "toString(...)"

    .line 217
    .line 218
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    const/16 p2, 0x10

    .line 222
    .line 223
    and-int/lit8 v0, p2, 0x2

    .line 224
    .line 225
    const/4 v2, 0x0

    .line 226
    if-eqz v0, :cond_3

    .line 227
    .line 228
    move v6, v3

    .line 229
    goto :goto_3

    .line 230
    :cond_3
    move v6, v2

    .line 231
    :goto_3
    and-int/lit8 v0, p2, 0x4

    .line 232
    .line 233
    if-eqz v0, :cond_4

    .line 234
    .line 235
    move v7, v3

    .line 236
    goto :goto_4

    .line 237
    :cond_4
    move v7, v2

    .line 238
    :goto_4
    and-int/lit8 v0, p2, 0x8

    .line 239
    .line 240
    if-eqz v0, :cond_5

    .line 241
    .line 242
    move v8, v2

    .line 243
    goto :goto_5

    .line 244
    :cond_5
    move v8, v3

    .line 245
    :goto_5
    and-int/2addr p2, p2

    .line 246
    if-eqz p2, :cond_6

    .line 247
    .line 248
    move v9, v2

    .line 249
    goto :goto_6

    .line 250
    :cond_6
    move v9, v3

    .line 251
    :goto_6
    iget-object p0, p0, Lkc0/f0;->c:Lbd0/c;

    .line 252
    .line 253
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 254
    .line 255
    new-instance v5, Ljava/net/URL;

    .line 256
    .line 257
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    move-object v4, p0

    .line 261
    check-cast v4, Lzc0/b;

    .line 262
    .line 263
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 264
    .line 265
    .line 266
    move-result-object p0

    .line 267
    iput v3, p3, Lkc0/e0;->f:I

    .line 268
    .line 269
    invoke-static {p0, p3}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    if-ne v0, v1, :cond_7

    .line 274
    .line 275
    return-object v1

    .line 276
    :cond_7
    :goto_7
    check-cast v0, Lne0/t;

    .line 277
    .line 278
    instance-of p0, v0, Lne0/c;

    .line 279
    .line 280
    if-nez p0, :cond_8

    .line 281
    .line 282
    new-instance p0, Lne0/e;

    .line 283
    .line 284
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 287
    .line 288
    .line 289
    return-object p0

    .line 290
    :cond_8
    check-cast v0, Lne0/c;

    .line 291
    .line 292
    iget-object p0, v0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 293
    .line 294
    throw p0

    .line 295
    :cond_9
    instance-of p0, p2, Lne0/c;

    .line 296
    .line 297
    if-eqz p0, :cond_a

    .line 298
    .line 299
    check-cast p2, Lne0/c;

    .line 300
    .line 301
    iget-object p0, p2, Lne0/c;->a:Ljava/lang/Throwable;

    .line 302
    .line 303
    throw p0

    .line 304
    :cond_a
    new-instance p0, La8/r0;

    .line 305
    .line 306
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 307
    .line 308
    .line 309
    throw p0
.end method

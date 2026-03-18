.class public final Ldw0/d;
.super Lcw0/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final m:Llx0/q;


# instance fields
.field public final h:Ldw0/a;

.field public final i:Ljava/util/Set;

.field public final j:Lpx0/g;

.field public final k:Lpx0/g;

.field public final l:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ldc/a;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ldc/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Ldw0/d;->m:Llx0/q;

    .line 13
    .line 14
    return-void
.end method

.method public constructor <init>(Ldw0/a;)V
    .locals 10

    .line 1
    const-string v0, "ktor-okhttp"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lcw0/e;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ldw0/d;->h:Ldw0/a;

    .line 7
    .line 8
    const/4 p1, 0x3

    .line 9
    new-array v0, p1, [Lcw0/f;

    .line 10
    .line 11
    sget-object v1, Lfw0/x0;->a:Lfw0/x0;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    aput-object v1, v0, v2

    .line 15
    .line 16
    sget-object v1, Ljw0/a;->a:Ljw0/a;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    aput-object v1, v0, v2

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    sget-object v2, Liw0/c;->a:Liw0/c;

    .line 23
    .line 24
    aput-object v2, v0, v1

    .line 25
    .line 26
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iput-object v0, p0, Ldw0/d;->i:Ljava/util/Set;

    .line 31
    .line 32
    new-instance v2, Lcz/j;

    .line 33
    .line 34
    const/4 v8, 0x0

    .line 35
    const/16 v9, 0x1b

    .line 36
    .line 37
    const/4 v3, 0x1

    .line 38
    const-class v5, Ldw0/d;

    .line 39
    .line 40
    const-string v6, "createOkHttpClient"

    .line 41
    .line 42
    const-string v7, "createOkHttpClient(Lio/ktor/client/plugins/HttpTimeoutConfig;)Lokhttp3/OkHttpClient;"

    .line 43
    .line 44
    move-object v4, p0

    .line 45
    invoke-direct/range {v2 .. v9}, Lcz/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 46
    .line 47
    .line 48
    new-instance p0, Ldj/a;

    .line 49
    .line 50
    const/16 v0, 0xa

    .line 51
    .line 52
    invoke-direct {p0, v0}, Ldj/a;-><init>(I)V

    .line 53
    .line 54
    .line 55
    new-instance v0, Lvw0/g;

    .line 56
    .line 57
    invoke-direct {v0, v2, p0}, Lvw0/g;-><init>(Lcz/j;Ldj/a;)V

    .line 58
    .line 59
    .line 60
    invoke-static {v0}, Ljava/util/Collections;->synchronizedMap(Ljava/util/Map;)Ljava/util/Map;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    const-string v0, "synchronizedMap(...)"

    .line 65
    .line 66
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iput-object p0, v4, Ldw0/d;->l:Ljava/util/Map;

    .line 70
    .line 71
    invoke-super {v4}, Lcw0/e;->getCoroutineContext()Lpx0/g;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-static {p0}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    new-instance v0, Lvy0/z1;

    .line 80
    .line 81
    invoke-direct {v0, p0}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 82
    .line 83
    .line 84
    new-instance p0, Lk4/r;

    .line 85
    .line 86
    sget-object v2, Lvy0/y;->d:Lvy0/y;

    .line 87
    .line 88
    invoke-direct {p0, v2, v1}, Lk4/r;-><init>(Lpx0/f;I)V

    .line 89
    .line 90
    .line 91
    invoke-static {v0, p0}, Ljp/ce;->a(Lpx0/g;Lpx0/g;)Lpx0/g;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    iput-object p0, v4, Ldw0/d;->j:Lpx0/g;

    .line 96
    .line 97
    invoke-super {v4}, Lcw0/e;->getCoroutineContext()Lpx0/g;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    invoke-interface {v0, p0}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    iput-object p0, v4, Ldw0/d;->k:Lpx0/g;

    .line 106
    .line 107
    invoke-super {v4}, Lcw0/e;->getCoroutineContext()Lpx0/g;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    sget-object v0, Lvy0/c0;->f:Lvy0/c0;

    .line 112
    .line 113
    new-instance v1, Ldm0/h;

    .line 114
    .line 115
    const/4 v2, 0x0

    .line 116
    invoke-direct {v1, v4, v2, p1}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 117
    .line 118
    .line 119
    sget-object p1, Lvy0/c1;->d:Lvy0/c1;

    .line 120
    .line 121
    invoke-static {p1, p0, v0, v1}, Lvy0/e0;->D(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;)Lvy0/x1;

    .line 122
    .line 123
    .line 124
    return-void
.end method


# virtual methods
.method public final a(Ld01/h0;Ld01/k0;Lpx0/g;Lss/b;Lrx0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object/from16 v0, p3

    .line 2
    .line 3
    move-object/from16 v1, p4

    .line 4
    .line 5
    move-object/from16 v2, p5

    .line 6
    .line 7
    instance-of v3, v2, Ldw0/c;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Ldw0/c;

    .line 13
    .line 14
    iget v4, v3, Ldw0/c;->i:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Ldw0/c;->i:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Ldw0/c;

    .line 27
    .line 28
    invoke-direct {v3, p0, v2}, Ldw0/c;-><init>(Ldw0/d;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object p0, v3, Ldw0/c;->g:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v4, v3, Ldw0/c;->i:I

    .line 36
    .line 37
    const/4 v5, 0x1

    .line 38
    const/4 v6, 0x0

    .line 39
    if-eqz v4, :cond_2

    .line 40
    .line 41
    if-ne v4, v5, :cond_1

    .line 42
    .line 43
    iget-object v0, v3, Ldw0/c;->f:Lxw0/d;

    .line 44
    .line 45
    iget-object v1, v3, Ldw0/c;->e:Lss/b;

    .line 46
    .line 47
    iget-object v2, v3, Ldw0/c;->d:Lpx0/g;

    .line 48
    .line 49
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    move-object v9, v0

    .line 53
    move-object v13, v2

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-static {v6}, Lxw0/a;->a(Ljava/lang/Long;)Lxw0/d;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    iput-object v0, v3, Ldw0/c;->d:Lpx0/g;

    .line 71
    .line 72
    iput-object v1, v3, Ldw0/c;->e:Lss/b;

    .line 73
    .line 74
    iput-object p0, v3, Ldw0/c;->f:Lxw0/d;

    .line 75
    .line 76
    iput v5, v3, Ldw0/c;->i:I

    .line 77
    .line 78
    new-instance v4, Lvy0/l;

    .line 79
    .line 80
    invoke-static {v3}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    invoke-direct {v4, v5, v3}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v4}, Lvy0/l;->q()V

    .line 88
    .line 89
    .line 90
    invoke-virtual/range {p1 .. p2}, Ld01/h0;->newCall(Ld01/k0;)Ld01/j;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    sget-object v7, Lvy0/h1;->d:Lvy0/h1;

    .line 95
    .line 96
    invoke-interface {v0, v7}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 97
    .line 98
    .line 99
    move-result-object v7

    .line 100
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    check-cast v7, Lvy0/i1;

    .line 104
    .line 105
    new-instance v8, Lag/t;

    .line 106
    .line 107
    move-object v9, v3

    .line 108
    check-cast v9, Lh01/o;

    .line 109
    .line 110
    const/4 v10, 0x4

    .line 111
    invoke-direct {v8, v9, v10}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 112
    .line 113
    .line 114
    invoke-interface {v7, v5, v5, v8}, Lvy0/i1;->f(ZZLay0/k;)Lvy0/r0;

    .line 115
    .line 116
    .line 117
    new-instance v5, Lb81/c;

    .line 118
    .line 119
    invoke-direct {v5, v1, v4}, Lb81/c;-><init>(Lss/b;Lvy0/l;)V

    .line 120
    .line 121
    .line 122
    invoke-static {v3, v5}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->enqueue(Ld01/j;Ld01/k;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v4}, Lvy0/l;->p()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    if-ne v3, v2, :cond_3

    .line 130
    .line 131
    return-object v2

    .line 132
    :cond_3
    move-object v9, p0

    .line 133
    move-object v13, v0

    .line 134
    move-object p0, v3

    .line 135
    :goto_1
    check-cast p0, Ld01/t0;

    .line 136
    .line 137
    iget-object v0, p0, Ld01/t0;->j:Ld01/v0;

    .line 138
    .line 139
    invoke-static {v13}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    new-instance v3, La2/e;

    .line 144
    .line 145
    const/16 v4, 0x17

    .line 146
    .line 147
    invoke-direct {v3, v0, v4}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 148
    .line 149
    .line 150
    invoke-interface {v2, v3}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0}, Ld01/v0;->p0()Lu01/h;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    new-instance v2, Ldw0/f;

    .line 158
    .line 159
    invoke-direct {v2, v0, v13, v1, v6}, Ldw0/f;-><init>(Lu01/h;Lpx0/g;Lss/b;Lkotlin/coroutines/Continuation;)V

    .line 160
    .line 161
    .line 162
    const/4 v0, 0x2

    .line 163
    sget-object v3, Lvy0/c1;->d:Lvy0/c1;

    .line 164
    .line 165
    invoke-static {v3, v13, v2, v0}, Lio/ktor/utils/io/h0;->p(Lvy0/b0;Lpx0/g;Lay0/n;I)Lb81/d;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    iget-object v0, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 170
    .line 171
    move-object v12, v0

    .line 172
    check-cast v12, Lio/ktor/utils/io/m;

    .line 173
    .line 174
    new-instance v8, Low0/v;

    .line 175
    .line 176
    iget v0, p0, Ld01/t0;->g:I

    .line 177
    .line 178
    iget-object v2, p0, Ld01/t0;->f:Ljava/lang/String;

    .line 179
    .line 180
    invoke-direct {v8, v0, v2}, Low0/v;-><init>(ILjava/lang/String;)V

    .line 181
    .line 182
    .line 183
    iget-object v0, p0, Ld01/t0;->e:Ld01/i0;

    .line 184
    .line 185
    const-string v2, "<this>"

    .line 186
    .line 187
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    sget-object v2, Low0/u;->e:Low0/u;

    .line 195
    .line 196
    packed-switch v0, :pswitch_data_0

    .line 197
    .line 198
    .line 199
    new-instance p0, La8/r0;

    .line 200
    .line 201
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 202
    .line 203
    .line 204
    throw p0

    .line 205
    :pswitch_0
    sget-object v2, Low0/u;->d:Low0/u;

    .line 206
    .line 207
    :goto_2
    :pswitch_1
    move-object v11, v2

    .line 208
    goto :goto_3

    .line 209
    :pswitch_2
    sget-object v2, Low0/u;->i:Low0/u;

    .line 210
    .line 211
    goto :goto_2

    .line 212
    :pswitch_3
    sget-object v2, Low0/u;->h:Low0/u;

    .line 213
    .line 214
    goto :goto_2

    .line 215
    :pswitch_4
    sget-object v2, Low0/u;->f:Low0/u;

    .line 216
    .line 217
    goto :goto_2

    .line 218
    :pswitch_5
    sget-object v2, Low0/u;->g:Low0/u;

    .line 219
    .line 220
    goto :goto_2

    .line 221
    :goto_3
    iget-object p0, p0, Ld01/t0;->i:Ld01/y;

    .line 222
    .line 223
    new-instance v10, Ldw0/g;

    .line 224
    .line 225
    invoke-direct {v10, p0}, Ldw0/g;-><init>(Ld01/y;)V

    .line 226
    .line 227
    .line 228
    instance-of p0, v12, Lio/ktor/utils/io/t;

    .line 229
    .line 230
    if-eqz p0, :cond_5

    .line 231
    .line 232
    iget-object p0, v1, Lss/b;->j:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast p0, Lvw0/d;

    .line 235
    .line 236
    sget-object v0, Lkw0/d;->a:Lvw0/a;

    .line 237
    .line 238
    invoke-virtual {p0, v0}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    if-nez p0, :cond_4

    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_4
    new-instance p0, Ljava/lang/ClassCastException;

    .line 246
    .line 247
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 248
    .line 249
    .line 250
    throw p0

    .line 251
    :cond_5
    :goto_4
    new-instance v7, Lkw0/f;

    .line 252
    .line 253
    invoke-direct/range {v7 .. v13}, Lkw0/f;-><init>(Low0/v;Lxw0/d;Low0/m;Low0/u;Ljava/lang/Object;Lpx0/g;)V

    .line 254
    .line 255
    .line 256
    return-object v7

    .line 257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_1
        :pswitch_1
        :pswitch_2
        :pswitch_0
    .end packed-switch
.end method

.method public final b0()Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Ldw0/d;->i:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public final close()V
    .locals 1

    .line 1
    invoke-super {p0}, Lcw0/e;->close()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Ldw0/d;->j:Lpx0/g;

    .line 5
    .line 6
    sget-object v0, Lvy0/h1;->d:Lvy0/h1;

    .line 7
    .line 8
    invoke-interface {p0, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "null cannot be cast to non-null type kotlinx.coroutines.CompletableJob"

    .line 13
    .line 14
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    check-cast p0, Lvy0/s;

    .line 18
    .line 19
    check-cast p0, Lvy0/k1;

    .line 20
    .line 21
    invoke-virtual {p0}, Lvy0/k1;->l0()Z

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ldw0/d;->k:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final p()Ldw0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ldw0/d;->h:Ldw0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s(Lss/b;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p2, Ldw0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ldw0/b;

    .line 7
    .line 8
    iget v1, v0, Ldw0/b;->g:I

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
    iput v1, v0, Ldw0/b;->g:I

    .line 18
    .line 19
    :goto_0
    move-object v6, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Ldw0/b;

    .line 22
    .line 23
    invoke-direct {v0, p0, p2}, Ldw0/b;-><init>(Ldw0/d;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object p2, v6, Ldw0/b;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v1, v6, Ldw0/b;->g:I

    .line 32
    .line 33
    const/4 v2, 0x3

    .line 34
    const/4 v3, 0x1

    .line 35
    if-eqz v1, :cond_5

    .line 36
    .line 37
    if-eq v1, v3, :cond_3

    .line 38
    .line 39
    const/4 p0, 0x2

    .line 40
    if-eq v1, p0, :cond_2

    .line 41
    .line 42
    if-ne v1, v2, :cond_1

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object p2

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-object p2

    .line 60
    :cond_3
    iget-object p1, v6, Ldw0/b;->d:Lss/b;

    .line 61
    .line 62
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_4
    move-object v5, p1

    .line 66
    goto :goto_2

    .line 67
    :cond_5
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput-object p1, v6, Ldw0/b;->d:Lss/b;

    .line 71
    .line 72
    iput v3, v6, Ldw0/b;->g:I

    .line 73
    .line 74
    sget-object p2, Lcw0/k;->a:Ljava/util/Set;

    .line 75
    .line 76
    invoke-interface {v6}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    sget-object v1, Lcw0/i;->e:Let/d;

    .line 81
    .line 82
    invoke-interface {p2, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    check-cast p2, Lcw0/i;

    .line 90
    .line 91
    iget-object p2, p2, Lcw0/i;->d:Lpx0/g;

    .line 92
    .line 93
    if-ne p2, v0, :cond_4

    .line 94
    .line 95
    goto/16 :goto_6

    .line 96
    .line 97
    :goto_2
    move-object v4, p2

    .line 98
    check-cast v4, Lpx0/g;

    .line 99
    .line 100
    new-instance p1, Ld01/j0;

    .line 101
    .line 102
    invoke-direct {p1}, Ld01/j0;-><init>()V

    .line 103
    .line 104
    .line 105
    iget-object p2, v5, Lss/b;->e:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p2, Low0/f0;

    .line 108
    .line 109
    iget-object v1, v5, Lss/b;->h:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v1, Lrw0/d;

    .line 112
    .line 113
    iget-object p2, p2, Low0/f0;->h:Ljava/lang/String;

    .line 114
    .line 115
    invoke-virtual {p1, p2}, Ld01/j0;->f(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    iget-object p2, v5, Lss/b;->f:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast p2, Low0/s;

    .line 121
    .line 122
    sget-object v7, Low0/t;->a:Ljava/util/Set;

    .line 123
    .line 124
    const-string v7, "<this>"

    .line 125
    .line 126
    invoke-static {p2, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    sget-object v7, Low0/t;->a:Ljava/util/Set;

    .line 130
    .line 131
    invoke-interface {v7, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v7

    .line 135
    iget-object p2, p2, Low0/s;->a:Ljava/lang/String;

    .line 136
    .line 137
    const/4 v8, 0x0

    .line 138
    if-eqz v7, :cond_6

    .line 139
    .line 140
    instance-of v7, v1, Lmw0/b;

    .line 141
    .line 142
    if-eqz v7, :cond_6

    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_6
    move v3, v8

    .line 146
    :goto_3
    iget-object v7, v5, Lss/b;->g:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v7, Low0/o;

    .line 149
    .line 150
    new-instance v9, Ldw0/e;

    .line 151
    .line 152
    invoke-direct {v9, v3, p1}, Ldw0/e;-><init>(ZLd01/j0;)V

    .line 153
    .line 154
    .line 155
    invoke-static {v7, v1, v9}, Lcw0/k;->a(Low0/o;Lrw0/d;Lay0/n;)V

    .line 156
    .line 157
    .line 158
    invoke-static {p2}, Llp/l1;->c(Ljava/lang/String;)Z

    .line 159
    .line 160
    .line 161
    move-result v3

    .line 162
    const/4 v7, 0x0

    .line 163
    if-eqz v3, :cond_b

    .line 164
    .line 165
    const-string v3, "callContext"

    .line 166
    .line 167
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    instance-of v3, v1, Lrw0/c;

    .line 171
    .line 172
    if-eqz v3, :cond_7

    .line 173
    .line 174
    move-object v3, v1

    .line 175
    check-cast v3, Lrw0/c;

    .line 176
    .line 177
    invoke-virtual {v3}, Lrw0/c;->d()[B

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    sget-object v9, Ld01/r0;->Companion:Ld01/q0;

    .line 182
    .line 183
    sget-object v10, Ld01/d0;->e:Lly0/n;

    .line 184
    .line 185
    invoke-virtual {v1}, Lrw0/d;->b()Low0/e;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-static {v1}, Ljp/ue;->e(Ljava/lang/String;)Ld01/d0;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    array-length v10, v3

    .line 198
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 199
    .line 200
    .line 201
    invoke-static {v1, v3, v8, v10}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    goto :goto_5

    .line 206
    :cond_7
    instance-of v3, v1, Lfw0/h;

    .line 207
    .line 208
    if-eqz v3, :cond_8

    .line 209
    .line 210
    new-instance v3, Ldw0/i;

    .line 211
    .line 212
    invoke-virtual {v1}, Lrw0/d;->a()Ljava/lang/Long;

    .line 213
    .line 214
    .line 215
    move-result-object v8

    .line 216
    new-instance v9, Ld2/g;

    .line 217
    .line 218
    const/4 v10, 0x4

    .line 219
    invoke-direct {v9, v1, v10}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 220
    .line 221
    .line 222
    invoke-direct {v3, v8, v9}, Ldw0/i;-><init>(Ljava/lang/Long;Lay0/a;)V

    .line 223
    .line 224
    .line 225
    :goto_4
    move-object v1, v3

    .line 226
    goto :goto_5

    .line 227
    :cond_8
    instance-of v3, v1, Lrw0/a;

    .line 228
    .line 229
    if-eqz v3, :cond_9

    .line 230
    .line 231
    new-instance v3, Ldw0/i;

    .line 232
    .line 233
    new-instance v8, Ld90/w;

    .line 234
    .line 235
    const/4 v9, 0x5

    .line 236
    invoke-direct {v8, v9, v4, v1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    invoke-direct {v3, v7, v8}, Ldw0/i;-><init>(Ljava/lang/Long;Lay0/a;)V

    .line 240
    .line 241
    .line 242
    goto :goto_4

    .line 243
    :cond_9
    instance-of v1, v1, Lmw0/b;

    .line 244
    .line 245
    if-eqz v1, :cond_a

    .line 246
    .line 247
    sget-object v1, Ld01/r0;->Companion:Ld01/q0;

    .line 248
    .line 249
    new-array v3, v8, [B

    .line 250
    .line 251
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 252
    .line 253
    .line 254
    invoke-static {v7, v3, v8, v8}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    goto :goto_5

    .line 259
    :cond_a
    new-instance p0, La8/r0;

    .line 260
    .line 261
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 262
    .line 263
    .line 264
    throw p0

    .line 265
    :cond_b
    move-object v1, v7

    .line 266
    :goto_5
    invoke-virtual {p1, p2, v1}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 267
    .line 268
    .line 269
    new-instance v3, Ld01/k0;

    .line 270
    .line 271
    invoke-direct {v3, p1}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 272
    .line 273
    .line 274
    iget-object p1, p0, Ldw0/d;->l:Ljava/util/Map;

    .line 275
    .line 276
    invoke-virtual {v5}, Lss/b;->g()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object p2

    .line 280
    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object p1

    .line 284
    check-cast p1, Ld01/h0;

    .line 285
    .line 286
    if-eqz p1, :cond_d

    .line 287
    .line 288
    sget-object p2, Lkw0/d;->a:Lvw0/a;

    .line 289
    .line 290
    iput-object v7, v6, Ldw0/b;->d:Lss/b;

    .line 291
    .line 292
    iput v2, v6, Ldw0/b;->g:I

    .line 293
    .line 294
    move-object v1, p0

    .line 295
    move-object v2, p1

    .line 296
    invoke-virtual/range {v1 .. v6}, Ldw0/d;->a(Ld01/h0;Ld01/k0;Lpx0/g;Lss/b;Lrx0/c;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    if-ne p0, v0, :cond_c

    .line 301
    .line 302
    :goto_6
    return-object v0

    .line 303
    :cond_c
    return-object p0

    .line 304
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 305
    .line 306
    const-string p1, "OkHttpClient can\'t be constructed because HttpTimeout plugin is not installed"

    .line 307
    .line 308
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    throw p0
.end method

.class public final Lod0/h0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:Ljava/lang/Object;

.field public e:Lne0/s;

.field public f:Lod0/q;

.field public g:I

.field public h:I

.field public final synthetic i:Lod0/i0;

.field public final synthetic j:Lne0/s;

.field public final synthetic k:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lod0/i0;Lne0/s;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lod0/h0;->i:Lod0/i0;

    .line 2
    .line 3
    iput-object p2, p0, Lod0/h0;->j:Lne0/s;

    .line 4
    .line 5
    iput-object p3, p0, Lod0/h0;->k:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lod0/h0;

    .line 2
    .line 3
    iget-object v1, p0, Lod0/h0;->j:Lne0/s;

    .line 4
    .line 5
    iget-object v2, p0, Lod0/h0;->k:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lod0/h0;->i:Lod0/i0;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p1}, Lod0/h0;-><init>(Lod0/i0;Lne0/s;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lod0/h0;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lod0/h0;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lod0/h0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lod0/h0;->h:I

    .line 6
    .line 7
    iget-object v3, v0, Lod0/h0;->j:Lne0/s;

    .line 8
    .line 9
    iget-object v4, v0, Lod0/h0;->k:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v5, 0x4

    .line 12
    const/4 v6, 0x3

    .line 13
    const/4 v7, 0x2

    .line 14
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    const/4 v9, 0x0

    .line 17
    iget-object v10, v0, Lod0/h0;->i:Lod0/i0;

    .line 18
    .line 19
    const/4 v11, 0x0

    .line 20
    const/4 v12, 0x1

    .line 21
    if-eqz v2, :cond_4

    .line 22
    .line 23
    if-eq v2, v12, :cond_3

    .line 24
    .line 25
    if-eq v2, v7, :cond_2

    .line 26
    .line 27
    if-eq v2, v6, :cond_1

    .line 28
    .line 29
    if-ne v2, v5, :cond_0

    .line 30
    .line 31
    iget-object v2, v0, Lod0/h0;->e:Lne0/s;

    .line 32
    .line 33
    check-cast v2, Lrd0/r;

    .line 34
    .line 35
    iget-object v2, v0, Lod0/h0;->d:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v2, Ljava/util/Iterator;

    .line 38
    .line 39
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto/16 :goto_5

    .line 43
    .line 44
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw v0

    .line 52
    :cond_1
    iget-object v2, v0, Lod0/h0;->d:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v2, Lod0/q;

    .line 55
    .line 56
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_4

    .line 60
    .line 61
    :cond_2
    iget v2, v0, Lod0/h0;->g:I

    .line 62
    .line 63
    iget-object v7, v0, Lod0/h0;->f:Lod0/q;

    .line 64
    .line 65
    iget-object v13, v0, Lod0/h0;->e:Lne0/s;

    .line 66
    .line 67
    iget-object v14, v0, Lod0/h0;->d:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v14, Ljava/lang/String;

    .line 70
    .line 71
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    move-object/from16 v2, p1

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object v2, v10, Lod0/i0;->d:Lti0/a;

    .line 85
    .line 86
    iput v12, v0, Lod0/h0;->h:I

    .line 87
    .line 88
    invoke-interface {v2, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    if-ne v2, v1, :cond_5

    .line 93
    .line 94
    goto/16 :goto_6

    .line 95
    .line 96
    :cond_5
    :goto_0
    check-cast v2, Lod0/q;

    .line 97
    .line 98
    iput-object v4, v0, Lod0/h0;->d:Ljava/lang/Object;

    .line 99
    .line 100
    iput-object v3, v0, Lod0/h0;->e:Lne0/s;

    .line 101
    .line 102
    iput-object v2, v0, Lod0/h0;->f:Lod0/q;

    .line 103
    .line 104
    iput v9, v0, Lod0/h0;->g:I

    .line 105
    .line 106
    iput v7, v0, Lod0/h0;->h:I

    .line 107
    .line 108
    iget-object v7, v2, Lod0/q;->a:Lla/u;

    .line 109
    .line 110
    new-instance v13, Lod0/d;

    .line 111
    .line 112
    const/4 v14, 0x3

    .line 113
    invoke-direct {v13, v4, v14}, Lod0/d;-><init>(Ljava/lang/String;I)V

    .line 114
    .line 115
    .line 116
    invoke-static {v0, v7, v9, v12, v13}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v7

    .line 120
    if-ne v7, v1, :cond_6

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_6
    move-object v7, v8

    .line 124
    :goto_1
    if-ne v7, v1, :cond_7

    .line 125
    .line 126
    goto :goto_6

    .line 127
    :cond_7
    move-object v7, v2

    .line 128
    move-object v13, v3

    .line 129
    move-object v14, v4

    .line 130
    move v2, v9

    .line 131
    :goto_2
    check-cast v13, Lne0/e;

    .line 132
    .line 133
    iget-object v13, v13, Lne0/e;->a:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v13, Lrd0/t;

    .line 136
    .line 137
    const-string v15, "$this$toEntity"

    .line 138
    .line 139
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    const-string v15, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 143
    .line 144
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    new-instance v15, Lod0/r;

    .line 148
    .line 149
    iget-object v5, v13, Lrd0/t;->a:Ljava/lang/Long;

    .line 150
    .line 151
    iget-object v9, v13, Lrd0/t;->b:Ljava/time/LocalTime;

    .line 152
    .line 153
    iget-object v13, v13, Lrd0/t;->d:Ljava/time/OffsetDateTime;

    .line 154
    .line 155
    invoke-direct {v15, v14, v5, v9, v13}, Lod0/r;-><init>(Ljava/lang/String;Ljava/lang/Long;Ljava/time/LocalTime;Ljava/time/OffsetDateTime;)V

    .line 156
    .line 157
    .line 158
    iput-object v11, v0, Lod0/h0;->d:Ljava/lang/Object;

    .line 159
    .line 160
    iput-object v11, v0, Lod0/h0;->e:Lne0/s;

    .line 161
    .line 162
    iput-object v11, v0, Lod0/h0;->f:Lod0/q;

    .line 163
    .line 164
    iput v2, v0, Lod0/h0;->g:I

    .line 165
    .line 166
    iput v6, v0, Lod0/h0;->h:I

    .line 167
    .line 168
    iget-object v2, v7, Lod0/q;->a:Lla/u;

    .line 169
    .line 170
    new-instance v5, Lod0/n;

    .line 171
    .line 172
    const/4 v6, 0x1

    .line 173
    invoke-direct {v5, v6, v7, v15}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    const/4 v6, 0x0

    .line 177
    invoke-static {v0, v2, v6, v12, v5}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    if-ne v2, v1, :cond_8

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_8
    move-object v2, v8

    .line 185
    :goto_3
    if-ne v2, v1, :cond_9

    .line 186
    .line 187
    goto :goto_6

    .line 188
    :cond_9
    :goto_4
    check-cast v3, Lne0/e;

    .line 189
    .line 190
    iget-object v2, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast v2, Lrd0/t;

    .line 193
    .line 194
    iget-object v2, v2, Lrd0/t;->c:Ljava/util/List;

    .line 195
    .line 196
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    :cond_a
    :goto_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 201
    .line 202
    .line 203
    move-result v3

    .line 204
    if-eqz v3, :cond_b

    .line 205
    .line 206
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v3

    .line 210
    check-cast v3, Lrd0/r;

    .line 211
    .line 212
    iput-object v2, v0, Lod0/h0;->d:Ljava/lang/Object;

    .line 213
    .line 214
    iput-object v11, v0, Lod0/h0;->e:Lne0/s;

    .line 215
    .line 216
    const/4 v5, 0x4

    .line 217
    iput v5, v0, Lod0/h0;->h:I

    .line 218
    .line 219
    invoke-static {v10, v4, v3, v0}, Lod0/i0;->b(Lod0/i0;Ljava/lang/String;Lrd0/r;Lrx0/c;)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    if-ne v3, v1, :cond_a

    .line 224
    .line 225
    :goto_6
    return-object v1

    .line 226
    :cond_b
    iget-object v0, v10, Lod0/i0;->f:Lwe0/a;

    .line 227
    .line 228
    check-cast v0, Lwe0/c;

    .line 229
    .line 230
    invoke-virtual {v0}, Lwe0/c;->c()V

    .line 231
    .line 232
    .line 233
    return-object v8
.end method

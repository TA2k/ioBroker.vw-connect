.class public final Llh0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ljh0/e;

.field public final b:Lkf0/o;

.field public final c:Loj0/d;

.field public final d:Llh0/d;

.field public final e:Llh0/e;


# direct methods
.method public constructor <init>(Ljh0/e;Lkf0/o;Loj0/d;Llh0/d;Llh0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llh0/j;->a:Ljh0/e;

    .line 5
    .line 6
    iput-object p2, p0, Llh0/j;->b:Lkf0/o;

    .line 7
    .line 8
    iput-object p3, p0, Llh0/j;->c:Loj0/d;

    .line 9
    .line 10
    iput-object p4, p0, Llh0/j;->d:Llh0/d;

    .line 11
    .line 12
    iput-object p5, p0, Llh0/j;->e:Llh0/e;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lmh0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Llh0/j;->b(Lmh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lmh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v2, p2, Llh0/i;

    .line 2
    .line 3
    if-eqz v2, :cond_0

    .line 4
    .line 5
    move-object v2, p2

    .line 6
    check-cast v2, Llh0/i;

    .line 7
    .line 8
    iget v3, v2, Llh0/i;->j:I

    .line 9
    .line 10
    const/high16 v4, -0x80000000

    .line 11
    .line 12
    and-int v5, v3, v4

    .line 13
    .line 14
    if-eqz v5, :cond_0

    .line 15
    .line 16
    sub-int/2addr v3, v4

    .line 17
    iput v3, v2, Llh0/i;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v2, Llh0/i;

    .line 21
    .line 22
    invoke-direct {v2, p0, p2}, Llh0/i;-><init>(Llh0/j;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object v1, v2, Llh0/i;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v4, v2, Llh0/i;->j:I

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    const/4 v6, 0x2

    .line 33
    const/4 v7, 0x1

    .line 34
    const/4 v8, 0x0

    .line 35
    if-eqz v4, :cond_4

    .line 36
    .line 37
    if-eq v4, v7, :cond_3

    .line 38
    .line 39
    if-eq v4, v6, :cond_2

    .line 40
    .line 41
    if-ne v4, v5, :cond_1

    .line 42
    .line 43
    iget-object v3, v2, Llh0/i;->g:Ljava/util/List;

    .line 44
    .line 45
    check-cast v3, Ljava/util/List;

    .line 46
    .line 47
    iget-object v4, v2, Llh0/i;->f:Lmh0/c;

    .line 48
    .line 49
    iget-object v5, v2, Llh0/i;->e:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v2, v2, Llh0/i;->d:Lmh0/a;

    .line 52
    .line 53
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    move-object v8, v3

    .line 57
    move-object v6, v5

    .line 58
    move-object v5, v4

    .line 59
    move-object v4, v2

    .line 60
    goto/16 :goto_6

    .line 61
    .line 62
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 65
    .line 66
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw v0

    .line 70
    :cond_2
    iget-object v4, v2, Llh0/i;->f:Lmh0/c;

    .line 71
    .line 72
    iget-object v6, v2, Llh0/i;->e:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v7, v2, Llh0/i;->d:Lmh0/a;

    .line 75
    .line 76
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_3
    iget-object v4, v2, Llh0/i;->d:Lmh0/a;

    .line 81
    .line 82
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    move-object v11, v4

    .line 86
    move-object v4, v1

    .line 87
    move-object v1, v11

    .line 88
    goto :goto_1

    .line 89
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    iput-object p1, v2, Llh0/i;->d:Lmh0/a;

    .line 93
    .line 94
    iput v7, v2, Llh0/i;->j:I

    .line 95
    .line 96
    iget-object v4, p0, Llh0/j;->b:Lkf0/o;

    .line 97
    .line 98
    invoke-virtual {v4, v2}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    if-ne v4, v3, :cond_5

    .line 103
    .line 104
    goto/16 :goto_5

    .line 105
    .line 106
    :cond_5
    move-object v1, p1

    .line 107
    :goto_1
    check-cast v4, Lne0/t;

    .line 108
    .line 109
    instance-of v7, v4, Lne0/c;

    .line 110
    .line 111
    if-eqz v7, :cond_6

    .line 112
    .line 113
    move-object v4, v8

    .line 114
    goto :goto_2

    .line 115
    :cond_6
    instance-of v7, v4, Lne0/e;

    .line 116
    .line 117
    if-eqz v7, :cond_b

    .line 118
    .line 119
    check-cast v4, Lne0/e;

    .line 120
    .line 121
    iget-object v4, v4, Lne0/e;->a:Ljava/lang/Object;

    .line 122
    .line 123
    :goto_2
    check-cast v4, Lss0/j0;

    .line 124
    .line 125
    if-eqz v4, :cond_7

    .line 126
    .line 127
    iget-object v4, v4, Lss0/j0;->d:Ljava/lang/String;

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_7
    move-object v4, v8

    .line 131
    :goto_3
    iget-object v7, p0, Llh0/j;->d:Llh0/d;

    .line 132
    .line 133
    invoke-virtual {v7}, Llh0/d;->invoke()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v7

    .line 137
    check-cast v7, Lmh0/c;

    .line 138
    .line 139
    iget-object v9, p0, Llh0/j;->e:Llh0/e;

    .line 140
    .line 141
    invoke-virtual {v9}, Llh0/e;->invoke()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v9

    .line 145
    check-cast v9, Lyy0/i;

    .line 146
    .line 147
    iput-object v1, v2, Llh0/i;->d:Lmh0/a;

    .line 148
    .line 149
    iput-object v4, v2, Llh0/i;->e:Ljava/lang/String;

    .line 150
    .line 151
    iput-object v7, v2, Llh0/i;->f:Lmh0/c;

    .line 152
    .line 153
    iput v6, v2, Llh0/i;->j:I

    .line 154
    .line 155
    invoke-static {v9, v2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v6

    .line 159
    if-ne v6, v3, :cond_8

    .line 160
    .line 161
    goto :goto_5

    .line 162
    :cond_8
    move-object v11, v7

    .line 163
    move-object v7, v1

    .line 164
    move-object v1, v6

    .line 165
    move-object v6, v4

    .line 166
    move-object v4, v11

    .line 167
    :goto_4
    check-cast v1, Ljava/util/List;

    .line 168
    .line 169
    if-eqz v1, :cond_9

    .line 170
    .line 171
    move-object v9, v1

    .line 172
    check-cast v9, Ljava/util/Collection;

    .line 173
    .line 174
    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    .line 175
    .line 176
    .line 177
    move-result v9

    .line 178
    if-nez v9, :cond_9

    .line 179
    .line 180
    move-object v8, v1

    .line 181
    :cond_9
    iput-object v7, v2, Llh0/i;->d:Lmh0/a;

    .line 182
    .line 183
    iput-object v6, v2, Llh0/i;->e:Ljava/lang/String;

    .line 184
    .line 185
    iput-object v4, v2, Llh0/i;->f:Lmh0/c;

    .line 186
    .line 187
    move-object v1, v8

    .line 188
    check-cast v1, Ljava/util/List;

    .line 189
    .line 190
    iput-object v1, v2, Llh0/i;->g:Ljava/util/List;

    .line 191
    .line 192
    iput v5, v2, Llh0/i;->j:I

    .line 193
    .line 194
    iget-object v1, p0, Llh0/j;->c:Loj0/d;

    .line 195
    .line 196
    invoke-virtual {v1, v2}, Loj0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    if-ne v1, v3, :cond_a

    .line 201
    .line 202
    :goto_5
    return-object v3

    .line 203
    :cond_a
    move-object v5, v4

    .line 204
    move-object v4, v7

    .line 205
    :goto_6
    move-object v7, v1

    .line 206
    check-cast v7, [B

    .line 207
    .line 208
    iget-object v3, p0, Llh0/j;->a:Ljh0/e;

    .line 209
    .line 210
    const-string v0, "feedback"

    .line 211
    .line 212
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    const-string v0, "metadata"

    .line 216
    .line 217
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    const-string v0, "logs"

    .line 221
    .line 222
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    iget-object v0, v3, Ljh0/e;->a:Lxl0/f;

    .line 226
    .line 227
    new-instance v2, Ljh0/d;

    .line 228
    .line 229
    const/4 v9, 0x0

    .line 230
    const/4 v10, 0x0

    .line 231
    invoke-direct/range {v2 .. v10}, Ljh0/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v0, v2}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    return-object v0

    .line 239
    :cond_b
    new-instance v0, La8/r0;

    .line 240
    .line 241
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 242
    .line 243
    .line 244
    throw v0
.end method

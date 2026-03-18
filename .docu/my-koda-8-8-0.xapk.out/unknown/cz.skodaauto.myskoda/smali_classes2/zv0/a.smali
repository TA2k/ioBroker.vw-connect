.class public final Lzv0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lga0/o;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lzv0/a;->d:I

    .line 1
    iput-object p2, p0, Lzv0/a;->h:Ljava/lang/Object;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lzv0/c;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lzv0/a;->d:I

    .line 2
    iput-object p1, p0, Lzv0/a;->h:Ljava/lang/Object;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lzv0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lyy0/j;

    .line 7
    .line 8
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    new-instance v0, Lzv0/a;

    .line 11
    .line 12
    iget-object p0, p0, Lzv0/a;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lga0/o;

    .line 15
    .line 16
    invoke-direct {v0, p3, p0}, Lzv0/a;-><init>(Lkotlin/coroutines/Continuation;Lga0/o;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, v0, Lzv0/a;->g:Ljava/lang/Object;

    .line 20
    .line 21
    iput-object p2, v0, Lzv0/a;->f:Ljava/lang/Object;

    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Lzv0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_0
    check-cast p1, Lyw0/e;

    .line 31
    .line 32
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 33
    .line 34
    new-instance v0, Lzv0/a;

    .line 35
    .line 36
    iget-object p0, p0, Lzv0/a;->h:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lzv0/c;

    .line 39
    .line 40
    invoke-direct {v0, p0, p3}, Lzv0/a;-><init>(Lzv0/c;Lkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    iput-object p1, v0, Lzv0/a;->g:Ljava/lang/Object;

    .line 44
    .line 45
    iput-object p2, v0, Lzv0/a;->f:Ljava/lang/Object;

    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    invoke-virtual {v0, p0}, Lzv0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lzv0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lzv0/a;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lzv0/a;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lyy0/j;

    .line 33
    .line 34
    iget-object v1, p0, Lzv0/a;->f:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v1, Lne0/t;

    .line 37
    .line 38
    instance-of v3, v1, Lne0/e;

    .line 39
    .line 40
    if-eqz v3, :cond_2

    .line 41
    .line 42
    check-cast v1, Lne0/e;

    .line 43
    .line 44
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v1, Lzb0/a;

    .line 47
    .line 48
    iget-object v1, p0, Lzv0/a;->h:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v1, Lga0/o;

    .line 51
    .line 52
    iget-object v1, v1, Lga0/o;->m:Lrt0/j;

    .line 53
    .line 54
    new-instance v3, Lrt0/h;

    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    invoke-direct {v3, v4}, Lrt0/h;-><init>(Z)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1, v3}, Lrt0/j;->a(Lrt0/h;)Lzy0/j;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    goto :goto_0

    .line 65
    :cond_2
    instance-of v3, v1, Lne0/c;

    .line 66
    .line 67
    if-eqz v3, :cond_4

    .line 68
    .line 69
    new-instance v3, Lyy0/m;

    .line 70
    .line 71
    const/4 v4, 0x0

    .line 72
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    move-object v1, v3

    .line 76
    :goto_0
    const/4 v3, 0x0

    .line 77
    iput-object v3, p0, Lzv0/a;->g:Ljava/lang/Object;

    .line 78
    .line 79
    iput-object v3, p0, Lzv0/a;->f:Ljava/lang/Object;

    .line 80
    .line 81
    iput v2, p0, Lzv0/a;->e:I

    .line 82
    .line 83
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-ne p0, v0, :cond_3

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    :goto_2
    return-object v0

    .line 93
    :cond_4
    new-instance p0, La8/r0;

    .line 94
    .line 95
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :pswitch_0
    iget-object v0, p0, Lzv0/a;->g:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lyw0/e;

    .line 102
    .line 103
    iget-object v1, p0, Lzv0/a;->f:Ljava/lang/Object;

    .line 104
    .line 105
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 106
    .line 107
    iget v3, p0, Lzv0/a;->e:I

    .line 108
    .line 109
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    const/4 v5, 0x2

    .line 112
    const/4 v6, 0x1

    .line 113
    if-eqz v3, :cond_8

    .line 114
    .line 115
    if-eq v3, v6, :cond_7

    .line 116
    .line 117
    if-ne v3, v5, :cond_6

    .line 118
    .line 119
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_5
    move-object v2, v4

    .line 123
    goto :goto_4

    .line 124
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 125
    .line 126
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 127
    .line 128
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw p0

    .line 132
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    instance-of p1, v1, Law0/c;

    .line 140
    .line 141
    if-eqz p1, :cond_a

    .line 142
    .line 143
    iget-object p1, p0, Lzv0/a;->h:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast p1, Lzv0/c;

    .line 146
    .line 147
    iget-object p1, p1, Lzv0/c;->l:Llw0/a;

    .line 148
    .line 149
    move-object v3, v1

    .line 150
    check-cast v3, Law0/c;

    .line 151
    .line 152
    invoke-virtual {v3}, Law0/c;->d()Law0/h;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    iput-object v0, p0, Lzv0/a;->g:Ljava/lang/Object;

    .line 157
    .line 158
    iput-object v1, p0, Lzv0/a;->f:Ljava/lang/Object;

    .line 159
    .line 160
    iput v6, p0, Lzv0/a;->e:I

    .line 161
    .line 162
    invoke-virtual {p1, v4, v3, p0}, Lyw0/d;->a(Ljava/lang/Object;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    if-ne p1, v2, :cond_9

    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_9
    :goto_3
    check-cast p1, Law0/h;

    .line 170
    .line 171
    move-object v3, v1

    .line 172
    check-cast v3, Law0/c;

    .line 173
    .line 174
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 175
    .line 176
    .line 177
    const-string v6, "response"

    .line 178
    .line 179
    invoke-static {p1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    iput-object p1, v3, Law0/c;->f:Law0/h;

    .line 183
    .line 184
    const/4 p1, 0x0

    .line 185
    iput-object p1, p0, Lzv0/a;->g:Ljava/lang/Object;

    .line 186
    .line 187
    iput-object p1, p0, Lzv0/a;->f:Ljava/lang/Object;

    .line 188
    .line 189
    iput v5, p0, Lzv0/a;->e:I

    .line 190
    .line 191
    invoke-virtual {v0, v1, p0}, Lyw0/e;->d(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    if-ne p0, v2, :cond_5

    .line 196
    .line 197
    :goto_4
    return-object v2

    .line 198
    :cond_a
    new-instance p0, Ljava/lang/StringBuilder;

    .line 199
    .line 200
    const-string p1, "Error: HttpClientCall expected, but found "

    .line 201
    .line 202
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    const/16 p1, 0x28

    .line 209
    .line 210
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 218
    .line 219
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 224
    .line 225
    .line 226
    const-string p1, ")."

    .line 227
    .line 228
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 236
    .line 237
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    throw p1

    .line 245
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

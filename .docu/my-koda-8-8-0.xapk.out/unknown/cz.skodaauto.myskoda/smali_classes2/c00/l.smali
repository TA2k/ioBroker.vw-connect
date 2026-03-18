.class public final Lc00/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lc00/p;


# direct methods
.method public synthetic constructor <init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/l;->g:Lc00/p;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lc00/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc00/l;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/l;->g:Lc00/p;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lc00/l;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lc00/l;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lc00/l;

    .line 18
    .line 19
    iget-object p0, p0, Lc00/l;->g:Lc00/p;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lc00/l;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lc00/l;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

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
    iget v0, p0, Lc00/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/c;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lc00/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/l;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lc00/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lc00/l;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lc00/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc00/l;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lc00/l;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lne0/c;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v3, v0, Lc00/l;->e:I

    .line 15
    .line 16
    const/4 v4, 0x1

    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    if-ne v3, v4, :cond_0

    .line 20
    .line 21
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw v0

    .line 33
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object v3, v0, Lc00/l;->g:Lc00/p;

    .line 37
    .line 38
    iget-object v3, v3, Lc00/p;->y:Lko0/f;

    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    iput-object v5, v0, Lc00/l;->f:Ljava/lang/Object;

    .line 42
    .line 43
    iput v4, v0, Lc00/l;->e:I

    .line 44
    .line 45
    invoke-virtual {v3, v1, v0}, Lko0/f;->b(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    if-ne v0, v2, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    :goto_0
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    :goto_1
    return-object v2

    .line 55
    :pswitch_0
    iget-object v1, v0, Lc00/l;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v1, Lne0/s;

    .line 58
    .line 59
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 60
    .line 61
    iget v3, v0, Lc00/l;->e:I

    .line 62
    .line 63
    const/4 v4, 0x1

    .line 64
    if-eqz v3, :cond_4

    .line 65
    .line 66
    if-ne v3, v4, :cond_3

    .line 67
    .line 68
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto/16 :goto_2

    .line 72
    .line 73
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw v0

    .line 81
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    instance-of v3, v1, Lne0/c;

    .line 85
    .line 86
    iget-object v5, v0, Lc00/l;->g:Lc00/p;

    .line 87
    .line 88
    if-eqz v3, :cond_5

    .line 89
    .line 90
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    check-cast v0, Lc00/n;

    .line 95
    .line 96
    iget-object v1, v5, Lc00/p;->l:Lij0/a;

    .line 97
    .line 98
    invoke-static {v0, v1}, Ljp/xb;->w(Lc00/n;Lij0/a;)Lc00/n;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 103
    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_5
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 107
    .line 108
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v3

    .line 112
    if-eqz v3, :cond_6

    .line 113
    .line 114
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    move-object v6, v0

    .line 119
    check-cast v6, Lc00/n;

    .line 120
    .line 121
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    check-cast v0, Lc00/n;

    .line 126
    .line 127
    iget-boolean v12, v0, Lc00/n;->g:Z

    .line 128
    .line 129
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    check-cast v0, Lc00/n;

    .line 134
    .line 135
    iget-boolean v13, v0, Lc00/n;->h:Z

    .line 136
    .line 137
    const/16 v17, 0x0

    .line 138
    .line 139
    const/16 v18, 0xf3f

    .line 140
    .line 141
    const/4 v7, 0x0

    .line 142
    const/4 v8, 0x0

    .line 143
    const/4 v9, 0x0

    .line 144
    const/4 v10, 0x0

    .line 145
    const/4 v11, 0x0

    .line 146
    const/4 v14, 0x0

    .line 147
    const/4 v15, 0x0

    .line 148
    const/16 v16, 0x0

    .line 149
    .line 150
    invoke-static/range {v6 .. v18}, Lc00/n;->a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 155
    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_6
    instance-of v3, v1, Lne0/e;

    .line 159
    .line 160
    if-eqz v3, :cond_9

    .line 161
    .line 162
    check-cast v1, Lne0/e;

    .line 163
    .line 164
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 165
    .line 166
    sget-object v3, Llf0/i;->j:Llf0/i;

    .line 167
    .line 168
    if-ne v1, v3, :cond_7

    .line 169
    .line 170
    new-instance v1, Lc00/k;

    .line 171
    .line 172
    const/4 v3, 0x1

    .line 173
    const/4 v6, 0x0

    .line 174
    invoke-direct {v1, v5, v6, v3}, Lc00/k;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 175
    .line 176
    .line 177
    iput-object v6, v0, Lc00/l;->f:Ljava/lang/Object;

    .line 178
    .line 179
    iput v4, v0, Lc00/l;->e:I

    .line 180
    .line 181
    invoke-static {v1, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    if-ne v0, v2, :cond_8

    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_7
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    move-object v6, v0

    .line 193
    check-cast v6, Lc00/n;

    .line 194
    .line 195
    move-object v11, v1

    .line 196
    check-cast v11, Llf0/i;

    .line 197
    .line 198
    const/16 v17, 0x0

    .line 199
    .line 200
    const/16 v18, 0xfcf

    .line 201
    .line 202
    const/4 v7, 0x0

    .line 203
    const/4 v8, 0x0

    .line 204
    const/4 v9, 0x0

    .line 205
    const/4 v10, 0x0

    .line 206
    const/4 v12, 0x0

    .line 207
    const/4 v13, 0x0

    .line 208
    const/4 v14, 0x0

    .line 209
    const/4 v15, 0x0

    .line 210
    const/16 v16, 0x0

    .line 211
    .line 212
    invoke-static/range {v6 .. v18}, Lc00/n;->a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 217
    .line 218
    .line 219
    :cond_8
    :goto_2
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    :goto_3
    return-object v2

    .line 222
    :cond_9
    new-instance v0, La8/r0;

    .line 223
    .line 224
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 225
    .line 226
    .line 227
    throw v0

    .line 228
    nop

    .line 229
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

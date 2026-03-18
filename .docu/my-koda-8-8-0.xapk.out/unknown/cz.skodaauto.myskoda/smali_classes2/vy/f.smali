.class public final Lvy/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lvy/h;


# direct methods
.method public synthetic constructor <init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvy/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvy/f;->g:Lvy/h;

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
    iget v0, p0, Lvy/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lvy/f;

    .line 7
    .line 8
    iget-object p0, p0, Lvy/f;->g:Lvy/h;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lvy/f;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lvy/f;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lvy/f;

    .line 18
    .line 19
    iget-object p0, p0, Lvy/f;->g:Lvy/h;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lvy/f;-><init>(Lvy/h;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lvy/f;->f:Ljava/lang/Object;

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
    iget v0, p0, Lvy/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lvy/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lvy/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lvy/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Llx0/l;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lvy/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lvy/f;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lvy/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvy/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lvy/f;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lvy0/b0;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v3, v0, Lvy/f;->e:I

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
    new-instance v3, Lvy/a;

    .line 37
    .line 38
    const/4 v5, 0x2

    .line 39
    iget-object v6, v0, Lvy/f;->g:Lvy/h;

    .line 40
    .line 41
    invoke-direct {v3, v6, v5}, Lvy/a;-><init>(Lvy/h;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {v1, v3}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 45
    .line 46
    .line 47
    iget-object v1, v6, Lvy/h;->o:Lty/k;

    .line 48
    .line 49
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Lyy0/i;

    .line 54
    .line 55
    new-instance v3, Lvy/c;

    .line 56
    .line 57
    invoke-direct {v3, v6, v5}, Lvy/c;-><init>(Lvy/h;I)V

    .line 58
    .line 59
    .line 60
    const/4 v5, 0x0

    .line 61
    iput-object v5, v0, Lvy/f;->f:Ljava/lang/Object;

    .line 62
    .line 63
    iput v4, v0, Lvy/f;->e:I

    .line 64
    .line 65
    invoke-interface {v1, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    if-ne v0, v2, :cond_2

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    :goto_0
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    :goto_1
    return-object v2

    .line 75
    :pswitch_0
    iget-object v1, v0, Lvy/f;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v1, Llx0/l;

    .line 78
    .line 79
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 80
    .line 81
    iget v3, v0, Lvy/f;->e:I

    .line 82
    .line 83
    const/4 v4, 0x1

    .line 84
    if-eqz v3, :cond_4

    .line 85
    .line 86
    if-ne v3, v4, :cond_3

    .line 87
    .line 88
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto/16 :goto_2

    .line 92
    .line 93
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 94
    .line 95
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 96
    .line 97
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw v0

    .line 101
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 105
    .line 106
    move-object v8, v3

    .line 107
    check-cast v8, Lne0/s;

    .line 108
    .line 109
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 110
    .line 111
    move-object v9, v1

    .line 112
    check-cast v9, Lcn0/c;

    .line 113
    .line 114
    instance-of v1, v8, Lne0/c;

    .line 115
    .line 116
    iget-object v6, v0, Lvy/f;->g:Lvy/h;

    .line 117
    .line 118
    if-eqz v1, :cond_5

    .line 119
    .line 120
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Lvy/d;

    .line 125
    .line 126
    iget-boolean v0, v0, Lvy/d;->d:Z

    .line 127
    .line 128
    if-eqz v0, :cond_7

    .line 129
    .line 130
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    check-cast v0, Lvy/d;

    .line 135
    .line 136
    iget-object v1, v6, Lvy/h;->k:Lij0/a;

    .line 137
    .line 138
    invoke-static {v0, v1}, Llp/oc;->d(Lvy/d;Lij0/a;)Lvy/d;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    invoke-virtual {v6, v0}, Lql0/j;->g(Lql0/h;)V

    .line 143
    .line 144
    .line 145
    goto :goto_2

    .line 146
    :cond_5
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 147
    .line 148
    invoke-static {v8, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-eqz v1, :cond_6

    .line 153
    .line 154
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    move-object v7, v0

    .line 159
    check-cast v7, Lvy/d;

    .line 160
    .line 161
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    check-cast v0, Lvy/d;

    .line 166
    .line 167
    iget-boolean v13, v0, Lvy/d;->h:Z

    .line 168
    .line 169
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    check-cast v0, Lvy/d;

    .line 174
    .line 175
    iget-boolean v14, v0, Lvy/d;->i:Z

    .line 176
    .line 177
    const/4 v15, 0x0

    .line 178
    const/16 v16, 0x27f

    .line 179
    .line 180
    const/4 v8, 0x0

    .line 181
    const/4 v9, 0x0

    .line 182
    const/4 v10, 0x0

    .line 183
    const/4 v11, 0x0

    .line 184
    const/4 v12, 0x0

    .line 185
    invoke-static/range {v7 .. v16}, Lvy/d;->a(Lvy/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;ZZZZZI)Lvy/d;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    invoke-virtual {v6, v0}, Lql0/j;->g(Lql0/h;)V

    .line 190
    .line 191
    .line 192
    goto :goto_2

    .line 193
    :cond_6
    instance-of v1, v8, Lne0/e;

    .line 194
    .line 195
    if-eqz v1, :cond_8

    .line 196
    .line 197
    new-instance v5, Lff/a;

    .line 198
    .line 199
    const/16 v11, 0xd

    .line 200
    .line 201
    const/4 v7, 0x0

    .line 202
    const/4 v10, 0x0

    .line 203
    invoke-direct/range {v5 .. v11}, Lff/a;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 204
    .line 205
    .line 206
    iput-object v10, v0, Lvy/f;->f:Ljava/lang/Object;

    .line 207
    .line 208
    iput v4, v0, Lvy/f;->e:I

    .line 209
    .line 210
    invoke-static {v5, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    if-ne v0, v2, :cond_7

    .line 215
    .line 216
    goto :goto_3

    .line 217
    :cond_7
    :goto_2
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 218
    .line 219
    :goto_3
    return-object v2

    .line 220
    :cond_8
    new-instance v0, La8/r0;

    .line 221
    .line 222
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 223
    .line 224
    .line 225
    throw v0

    .line 226
    nop

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

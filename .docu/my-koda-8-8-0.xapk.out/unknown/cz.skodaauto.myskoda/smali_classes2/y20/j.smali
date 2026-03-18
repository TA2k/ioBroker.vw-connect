.class public final Ly20/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ly20/m;


# direct methods
.method public synthetic constructor <init>(Ly20/m;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly20/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly20/j;->g:Ly20/m;

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
    iget v0, p0, Ly20/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ly20/j;

    .line 7
    .line 8
    iget-object p0, p0, Ly20/j;->g:Ly20/m;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Ly20/j;-><init>(Ly20/m;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Ly20/j;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ly20/j;

    .line 18
    .line 19
    iget-object p0, p0, Ly20/j;->g:Ly20/m;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Ly20/j;-><init>(Ly20/m;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Ly20/j;->f:Ljava/lang/Object;

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
    iget v0, p0, Ly20/j;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly20/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly20/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly20/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly20/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ly20/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ly20/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ly20/j;->d:I

    .line 4
    .line 5
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    iget-object v4, v0, Ly20/j;->g:Ly20/m;

    .line 9
    .line 10
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    packed-switch v1, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    iget-object v1, v0, Ly20/j;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Lvy0/b0;

    .line 18
    .line 19
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v7, v0, Ly20/j;->e:I

    .line 22
    .line 23
    if-eqz v7, :cond_1

    .line 24
    .line 25
    if-ne v7, v3, :cond_0

    .line 26
    .line 27
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget-object v2, v4, Ly20/m;->F:Lgt0/d;

    .line 41
    .line 42
    iput-object v1, v0, Ly20/j;->f:Ljava/lang/Object;

    .line 43
    .line 44
    iput v3, v0, Ly20/j;->e:I

    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v2, v0}, Lgt0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    if-ne v0, v6, :cond_2

    .line 54
    .line 55
    move-object v5, v6

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    :goto_0
    sget-object v0, Ly20/m;->H:Ljava/util/List;

    .line 58
    .line 59
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    check-cast v0, Ly20/h;

    .line 64
    .line 65
    invoke-virtual {v0}, Ly20/h;->b()Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-eqz v0, :cond_3

    .line 70
    .line 71
    new-instance v0, Lxf/b;

    .line 72
    .line 73
    const/16 v2, 0xf

    .line 74
    .line 75
    invoke-direct {v0, v2}, Lxf/b;-><init>(I)V

    .line 76
    .line 77
    .line 78
    invoke-static {v1, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    new-instance v0, Lxf/b;

    .line 83
    .line 84
    const/16 v2, 0x10

    .line 85
    .line 86
    invoke-direct {v0, v2}, Lxf/b;-><init>(I)V

    .line 87
    .line 88
    .line 89
    invoke-static {v1, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 90
    .line 91
    .line 92
    :goto_1
    return-object v5

    .line 93
    :pswitch_0
    iget-object v1, v0, Ly20/j;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v1, Lvy0/b0;

    .line 96
    .line 97
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    iget v7, v0, Ly20/j;->e:I

    .line 100
    .line 101
    if-eqz v7, :cond_5

    .line 102
    .line 103
    if-ne v7, v3, :cond_4

    .line 104
    .line 105
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw v0

    .line 115
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    new-instance v2, Ly20/a;

    .line 119
    .line 120
    const/4 v7, 0x3

    .line 121
    invoke-direct {v2, v4, v7}, Ly20/a;-><init>(Ly20/m;I)V

    .line 122
    .line 123
    .line 124
    invoke-static {v1, v2}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 125
    .line 126
    .line 127
    sget-object v1, Ly20/m;->H:Ljava/util/List;

    .line 128
    .line 129
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    move-object v7, v1

    .line 134
    check-cast v7, Ly20/h;

    .line 135
    .line 136
    const/16 v23, 0x0

    .line 137
    .line 138
    const v24, 0xfffe

    .line 139
    .line 140
    .line 141
    const/4 v8, 0x0

    .line 142
    const/4 v9, 0x0

    .line 143
    const/4 v10, 0x0

    .line 144
    const/4 v11, 0x0

    .line 145
    const/4 v12, 0x0

    .line 146
    const/4 v13, 0x0

    .line 147
    const/4 v14, 0x0

    .line 148
    const/4 v15, 0x0

    .line 149
    const/16 v16, 0x0

    .line 150
    .line 151
    const/16 v17, 0x0

    .line 152
    .line 153
    const/16 v18, 0x0

    .line 154
    .line 155
    const/16 v19, 0x0

    .line 156
    .line 157
    const/16 v20, 0x0

    .line 158
    .line 159
    const/16 v21, 0x0

    .line 160
    .line 161
    const/16 v22, 0x0

    .line 162
    .line 163
    invoke-static/range {v7 .. v24}, Ly20/h;->a(Ly20/h;Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;I)Ly20/h;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    invoke-virtual {v4, v1}, Lql0/j;->g(Lql0/h;)V

    .line 168
    .line 169
    .line 170
    const/4 v1, 0x0

    .line 171
    iput-object v1, v0, Ly20/j;->f:Ljava/lang/Object;

    .line 172
    .line 173
    iput v3, v0, Ly20/j;->e:I

    .line 174
    .line 175
    const/4 v1, 0x0

    .line 176
    invoke-virtual {v4, v1, v0}, Ly20/m;->k(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    if-ne v0, v6, :cond_6

    .line 181
    .line 182
    move-object v5, v6

    .line 183
    :cond_6
    :goto_2
    return-object v5

    .line 184
    nop

    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.class public final Lt1/z;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lp3/x;

.field public final synthetic g:Lt1/w0;


# direct methods
.method public synthetic constructor <init>(Lp3/x;Lt1/w0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lt1/z;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt1/z;->f:Lp3/x;

    .line 4
    .line 5
    iput-object p2, p0, Lt1/z;->g:Lt1/w0;

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
    iget p1, p0, Lt1/z;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lt1/z;

    .line 7
    .line 8
    iget-object v0, p0, Lt1/z;->g:Lt1/w0;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    iget-object p0, p0, Lt1/z;->f:Lp3/x;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lt1/z;-><init>(Lp3/x;Lt1/w0;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lt1/z;

    .line 18
    .line 19
    iget-object v0, p0, Lt1/z;->g:Lt1/w0;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iget-object p0, p0, Lt1/z;->f:Lp3/x;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lt1/z;-><init>(Lp3/x;Lt1/w0;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Lt1/z;

    .line 29
    .line 30
    iget-object v0, p0, Lt1/z;->g:Lt1/w0;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object p0, p0, Lt1/z;->f:Lp3/x;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Lt1/z;-><init>(Lp3/x;Lt1/w0;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lt1/z;->d:I

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
    invoke-virtual {p0, p1, p2}, Lt1/z;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lt1/z;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lt1/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lt1/z;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lt1/z;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lt1/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lt1/z;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lt1/z;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lt1/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lt1/z;->d:I

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    const/4 v3, 0x0

    .line 7
    iget-object v4, v0, Lt1/z;->g:Lt1/w0;

    .line 8
    .line 9
    iget-object v5, v0, Lt1/z;->f:Lp3/x;

    .line 10
    .line 11
    const-string v6, "call to \'resume\' before \'invoke\' with coroutine"

    .line 12
    .line 13
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    const/4 v8, 0x1

    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v2, v0, Lt1/z;->e:I

    .line 22
    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    if-ne v2, v8, :cond_0

    .line 26
    .line 27
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_3

    .line 31
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iput v8, v0, Lt1/z;->e:I

    .line 41
    .line 42
    new-instance v2, Le2/v;

    .line 43
    .line 44
    invoke-direct {v2, v4, v8}, Le2/v;-><init>(Lt1/w0;I)V

    .line 45
    .line 46
    .line 47
    new-instance v3, Lt1/r0;

    .line 48
    .line 49
    const/4 v6, 0x0

    .line 50
    invoke-direct {v3, v4, v6}, Lt1/r0;-><init>(Lt1/w0;I)V

    .line 51
    .line 52
    .line 53
    new-instance v15, Lt1/r0;

    .line 54
    .line 55
    invoke-direct {v15, v4, v8}, Lt1/r0;-><init>(Lt1/w0;I)V

    .line 56
    .line 57
    .line 58
    new-instance v14, Llk/c;

    .line 59
    .line 60
    const/16 v6, 0x1a

    .line 61
    .line 62
    invoke-direct {v14, v4, v6}, Llk/c;-><init>(Ljava/lang/Object;I)V

    .line 63
    .line 64
    .line 65
    sget v4, Lg1/w0;->a:F

    .line 66
    .line 67
    new-instance v13, Lak/l;

    .line 68
    .line 69
    const/16 v4, 0xb

    .line 70
    .line 71
    invoke-direct {v13, v4, v2}, Lak/l;-><init>(ILay0/k;)V

    .line 72
    .line 73
    .line 74
    new-instance v2, Laj0/c;

    .line 75
    .line 76
    const/16 v4, 0x17

    .line 77
    .line 78
    invoke-direct {v2, v3, v4}, Laj0/c;-><init>(Lay0/a;I)V

    .line 79
    .line 80
    .line 81
    new-instance v10, Lf2/h0;

    .line 82
    .line 83
    const/16 v3, 0xf

    .line 84
    .line 85
    invoke-direct {v10, v3}, Lf2/h0;-><init>(I)V

    .line 86
    .line 87
    .line 88
    new-instance v11, Lkotlin/jvm/internal/e0;

    .line 89
    .line 90
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 91
    .line 92
    .line 93
    new-instance v9, Lg1/q0;

    .line 94
    .line 95
    const/16 v17, 0x0

    .line 96
    .line 97
    const/4 v12, 0x0

    .line 98
    move-object/from16 v16, v2

    .line 99
    .line 100
    invoke-direct/range {v9 .. v17}, Lg1/q0;-><init>(Lay0/a;Lkotlin/jvm/internal/e0;Lg1/w1;Lay0/o;Lay0/n;Lay0/a;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 101
    .line 102
    .line 103
    invoke-static {v5, v9, v0}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    if-ne v0, v1, :cond_2

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_2
    move-object v0, v7

    .line 111
    :goto_0
    if-ne v0, v1, :cond_3

    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_3
    move-object v0, v7

    .line 115
    :goto_1
    if-ne v0, v1, :cond_4

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_4
    move-object v0, v7

    .line 119
    :goto_2
    if-ne v0, v1, :cond_5

    .line 120
    .line 121
    move-object v7, v1

    .line 122
    :cond_5
    :goto_3
    return-object v7

    .line 123
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 124
    .line 125
    iget v9, v0, Lt1/z;->e:I

    .line 126
    .line 127
    if-eqz v9, :cond_7

    .line 128
    .line 129
    if-ne v9, v8, :cond_6

    .line 130
    .line 131
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    goto :goto_5

    .line 135
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 136
    .line 137
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw v0

    .line 141
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    iput v8, v0, Lt1/z;->e:I

    .line 145
    .line 146
    new-instance v6, Lg1/l1;

    .line 147
    .line 148
    invoke-direct {v6, v4, v3, v2}, Lg1/l1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 149
    .line 150
    .line 151
    invoke-static {v5, v6, v0}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    if-ne v0, v1, :cond_8

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_8
    move-object v0, v7

    .line 159
    :goto_4
    if-ne v0, v1, :cond_9

    .line 160
    .line 161
    move-object v7, v1

    .line 162
    :cond_9
    :goto_5
    return-object v7

    .line 163
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 164
    .line 165
    iget v9, v0, Lt1/z;->e:I

    .line 166
    .line 167
    if-eqz v9, :cond_b

    .line 168
    .line 169
    if-ne v9, v8, :cond_a

    .line 170
    .line 171
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    goto :goto_7

    .line 175
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 176
    .line 177
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    throw v0

    .line 181
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    iput v8, v0, Lt1/z;->e:I

    .line 185
    .line 186
    new-instance v6, Lqh/a;

    .line 187
    .line 188
    invoke-direct {v6, v2, v5, v4, v3}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 189
    .line 190
    .line 191
    invoke-static {v6, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    if-ne v0, v1, :cond_c

    .line 196
    .line 197
    goto :goto_6

    .line 198
    :cond_c
    move-object v0, v7

    .line 199
    :goto_6
    if-ne v0, v1, :cond_d

    .line 200
    .line 201
    move-object v7, v1

    .line 202
    :cond_d
    :goto_7
    return-object v7

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

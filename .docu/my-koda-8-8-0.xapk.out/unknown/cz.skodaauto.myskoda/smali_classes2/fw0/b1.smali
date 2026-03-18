.class public final Lfw0/b1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyw0/e;

.field public final synthetic g:Lay0/o;


# direct methods
.method public synthetic constructor <init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lfw0/b1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfw0/b1;->g:Lay0/o;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lfw0/b1;->d:I

    .line 2
    .line 3
    check-cast p1, Lyw0/e;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    new-instance p2, Lfw0/b1;

    .line 11
    .line 12
    iget-object p0, p0, Lfw0/b1;->g:Lay0/o;

    .line 13
    .line 14
    const/4 v0, 0x2

    .line 15
    invoke-direct {p2, p0, p3, v0}, Lfw0/b1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p2, Lfw0/b1;->f:Lyw0/e;

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {p2, p0}, Lfw0/b1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_0
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    new-instance p2, Lfw0/b1;

    .line 30
    .line 31
    iget-object p0, p0, Lfw0/b1;->g:Lay0/o;

    .line 32
    .line 33
    const/4 v0, 0x1

    .line 34
    invoke-direct {p2, p0, p3, v0}, Lfw0/b1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p2, Lfw0/b1;->f:Lyw0/e;

    .line 38
    .line 39
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    invoke-virtual {p2, p0}, Lfw0/b1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :pswitch_1
    check-cast p2, Llw0/b;

    .line 47
    .line 48
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 49
    .line 50
    new-instance p2, Lfw0/b1;

    .line 51
    .line 52
    iget-object p0, p0, Lfw0/b1;->g:Lay0/o;

    .line 53
    .line 54
    const/4 v0, 0x0

    .line 55
    invoke-direct {p2, p0, p3, v0}, Lfw0/b1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    iput-object p1, p2, Lfw0/b1;->f:Lyw0/e;

    .line 59
    .line 60
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    invoke-virtual {p2, p0}, Lfw0/b1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget v0, v1, Lfw0/b1;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    iget-object v5, v1, Lfw0/b1;->g:Lay0/o;

    .line 10
    .line 11
    const-string v6, "call to \'resume\' before \'invoke\' with coroutine"

    .line 12
    .line 13
    const/4 v7, 0x1

    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    iget-object v10, v1, Lfw0/b1;->f:Lyw0/e;

    .line 18
    .line 19
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v2, v1, Lfw0/b1;->e:I

    .line 22
    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    if-ne v2, v7, :cond_0

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
    iget-object v2, v10, Lyw0/e;->d:Ljava/lang/Object;

    .line 41
    .line 42
    new-instance v8, Lc4/i;

    .line 43
    .line 44
    const/16 v14, 0x8

    .line 45
    .line 46
    const/4 v15, 0x5

    .line 47
    const/4 v9, 0x1

    .line 48
    const-class v11, Lyw0/e;

    .line 49
    .line 50
    const-string v12, "proceed"

    .line 51
    .line 52
    const-string v13, "proceed(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 53
    .line 54
    invoke-direct/range {v8 .. v15}, Lc4/i;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 55
    .line 56
    .line 57
    iput-object v4, v1, Lfw0/b1;->f:Lyw0/e;

    .line 58
    .line 59
    iput v7, v1, Lfw0/b1;->e:I

    .line 60
    .line 61
    invoke-interface {v5, v2, v8, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    if-ne v1, v0, :cond_2

    .line 66
    .line 67
    move-object v3, v0

    .line 68
    :cond_2
    :goto_0
    return-object v3

    .line 69
    :pswitch_0
    iget-object v8, v1, Lfw0/b1;->f:Lyw0/e;

    .line 70
    .line 71
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    iget v0, v1, Lfw0/b1;->e:I

    .line 74
    .line 75
    if-eqz v0, :cond_5

    .line 76
    .line 77
    if-eq v0, v7, :cond_4

    .line 78
    .line 79
    if-ne v0, v2, :cond_3

    .line 80
    .line 81
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    move-object/from16 v0, p1

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 88
    .line 89
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw v0

    .line 93
    :cond_4
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    .line 95
    .line 96
    goto :goto_4

    .line 97
    :catchall_0
    move-exception v0

    .line 98
    goto :goto_1

    .line 99
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    :try_start_1
    iput-object v8, v1, Lfw0/b1;->f:Lyw0/e;

    .line 103
    .line 104
    iput v7, v1, Lfw0/b1;->e:I

    .line 105
    .line 106
    invoke-virtual {v8, v1}, Lyw0/e;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 110
    if-ne v0, v9, :cond_7

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :goto_1
    iget-object v6, v8, Lyw0/e;->d:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v6, Lkw0/c;

    .line 116
    .line 117
    sget-object v7, Lfw0/s;->a:Lt21/b;

    .line 118
    .line 119
    new-instance v7, Lfw0/r;

    .line 120
    .line 121
    invoke-direct {v7, v6}, Lfw0/r;-><init>(Lkw0/c;)V

    .line 122
    .line 123
    .line 124
    iput-object v4, v1, Lfw0/b1;->f:Lyw0/e;

    .line 125
    .line 126
    iput v2, v1, Lfw0/b1;->e:I

    .line 127
    .line 128
    invoke-interface {v5, v7, v0, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    if-ne v0, v9, :cond_6

    .line 133
    .line 134
    :goto_2
    move-object v3, v9

    .line 135
    goto :goto_4

    .line 136
    :cond_6
    :goto_3
    check-cast v0, Ljava/lang/Throwable;

    .line 137
    .line 138
    if-nez v0, :cond_8

    .line 139
    .line 140
    :cond_7
    :goto_4
    return-object v3

    .line 141
    :cond_8
    throw v0

    .line 142
    :pswitch_1
    iget-object v8, v1, Lfw0/b1;->f:Lyw0/e;

    .line 143
    .line 144
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 145
    .line 146
    iget v0, v1, Lfw0/b1;->e:I

    .line 147
    .line 148
    if-eqz v0, :cond_b

    .line 149
    .line 150
    if-eq v0, v7, :cond_a

    .line 151
    .line 152
    if-ne v0, v2, :cond_9

    .line 153
    .line 154
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    move-object/from16 v0, p1

    .line 158
    .line 159
    goto :goto_7

    .line 160
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 161
    .line 162
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    throw v0

    .line 166
    :cond_a
    :try_start_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 167
    .line 168
    .line 169
    goto :goto_8

    .line 170
    :catchall_1
    move-exception v0

    .line 171
    goto :goto_5

    .line 172
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    :try_start_3
    iput-object v8, v1, Lfw0/b1;->f:Lyw0/e;

    .line 176
    .line 177
    iput v7, v1, Lfw0/b1;->e:I

    .line 178
    .line 179
    invoke-virtual {v8, v1}, Lyw0/e;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 183
    if-ne v0, v9, :cond_d

    .line 184
    .line 185
    goto :goto_6

    .line 186
    :goto_5
    iget-object v6, v8, Lyw0/e;->d:Ljava/lang/Object;

    .line 187
    .line 188
    check-cast v6, Law0/c;

    .line 189
    .line 190
    invoke-virtual {v6}, Law0/c;->c()Lkw0/b;

    .line 191
    .line 192
    .line 193
    move-result-object v6

    .line 194
    iput-object v4, v1, Lfw0/b1;->f:Lyw0/e;

    .line 195
    .line 196
    iput v2, v1, Lfw0/b1;->e:I

    .line 197
    .line 198
    invoke-interface {v5, v6, v0, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    if-ne v0, v9, :cond_c

    .line 203
    .line 204
    :goto_6
    move-object v3, v9

    .line 205
    goto :goto_8

    .line 206
    :cond_c
    :goto_7
    check-cast v0, Ljava/lang/Throwable;

    .line 207
    .line 208
    if-nez v0, :cond_e

    .line 209
    .line 210
    :cond_d
    :goto_8
    return-object v3

    .line 211
    :cond_e
    throw v0

    .line 212
    nop

    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

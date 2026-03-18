.class public final Lg1/y0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lhu/o0;Lhu/j0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lg1/y0;->d:I

    .line 1
    iput-object p1, p0, Lg1/y0;->l:Ljava/lang/Object;

    iput-object p2, p0, Lg1/y0;->m:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p9, p0, Lg1/y0;->d:I

    iput-object p1, p0, Lg1/y0;->g:Ljava/lang/Object;

    iput-object p2, p0, Lg1/y0;->h:Ljava/lang/Object;

    iput-object p3, p0, Lg1/y0;->i:Ljava/lang/Object;

    iput-object p4, p0, Lg1/y0;->j:Ljava/lang/Object;

    iput-object p5, p0, Lg1/y0;->k:Ljava/lang/Object;

    iput-object p6, p0, Lg1/y0;->l:Ljava/lang/Object;

    iput-object p7, p0, Lg1/y0;->m:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p8}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 12

    .line 1
    iget v0, p0, Lg1/y0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lg1/y0;

    .line 7
    .line 8
    iget-object p1, p0, Lg1/y0;->g:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    check-cast v2, Li91/r2;

    .line 12
    .line 13
    iget-object p1, p0, Lg1/y0;->h:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, p1

    .line 16
    check-cast v3, Ll2/b1;

    .line 17
    .line 18
    iget-object p1, p0, Lg1/y0;->i:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, p1

    .line 21
    check-cast v4, Ll2/t2;

    .line 22
    .line 23
    iget-object p1, p0, Lg1/y0;->j:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v5, p1

    .line 26
    check-cast v5, Lw3/j2;

    .line 27
    .line 28
    iget-object p1, p0, Lg1/y0;->k:Ljava/lang/Object;

    .line 29
    .line 30
    move-object v6, p1

    .line 31
    check-cast v6, Luu/g;

    .line 32
    .line 33
    iget-object p1, p0, Lg1/y0;->l:Ljava/lang/Object;

    .line 34
    .line 35
    move-object v7, p1

    .line 36
    check-cast v7, Ll2/b1;

    .line 37
    .line 38
    iget-object p0, p0, Lg1/y0;->m:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v8, p0

    .line 41
    check-cast v8, Ll2/b1;

    .line 42
    .line 43
    const/4 v10, 0x3

    .line 44
    move-object v9, p2

    .line 45
    invoke-direct/range {v1 .. v10}, Lg1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    return-object v1

    .line 49
    :pswitch_0
    move-object v10, p2

    .line 50
    new-instance p1, Lg1/y0;

    .line 51
    .line 52
    iget-object p2, p0, Lg1/y0;->l:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p2, Lhu/o0;

    .line 55
    .line 56
    iget-object p0, p0, Lg1/y0;->m:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Lhu/j0;

    .line 59
    .line 60
    invoke-direct {p1, p2, p0, v10}, Lg1/y0;-><init>(Lhu/o0;Lhu/j0;Lkotlin/coroutines/Continuation;)V

    .line 61
    .line 62
    .line 63
    return-object p1

    .line 64
    :pswitch_1
    move-object v10, p2

    .line 65
    new-instance v2, Lg1/y0;

    .line 66
    .line 67
    iget-object p2, p0, Lg1/y0;->g:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v3, p2

    .line 70
    check-cast v3, Ll2/y1;

    .line 71
    .line 72
    iget-object p2, p0, Lg1/y0;->h:Ljava/lang/Object;

    .line 73
    .line 74
    move-object v4, p2

    .line 75
    check-cast v4, La7/n;

    .line 76
    .line 77
    iget-object p2, p0, Lg1/y0;->i:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v5, p2

    .line 80
    check-cast v5, Lyy0/c2;

    .line 81
    .line 82
    iget-object p2, p0, Lg1/y0;->j:Ljava/lang/Object;

    .line 83
    .line 84
    move-object v6, p2

    .line 85
    check-cast v6, Landroid/content/Context;

    .line 86
    .line 87
    iget-object p2, p0, Lg1/y0;->k:Ljava/lang/Object;

    .line 88
    .line 89
    move-object v7, p2

    .line 90
    check-cast v7, La7/q1;

    .line 91
    .line 92
    iget-object p2, p0, Lg1/y0;->l:Ljava/lang/Object;

    .line 93
    .line 94
    move-object v8, p2

    .line 95
    check-cast v8, Lh7/a0;

    .line 96
    .line 97
    iget-object p0, p0, Lg1/y0;->m:Ljava/lang/Object;

    .line 98
    .line 99
    move-object v9, p0

    .line 100
    check-cast v9, Lh7/x;

    .line 101
    .line 102
    const/4 v11, 0x1

    .line 103
    invoke-direct/range {v2 .. v11}, Lg1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 104
    .line 105
    .line 106
    iput-object p1, v2, Lg1/y0;->f:Ljava/lang/Object;

    .line 107
    .line 108
    return-object v2

    .line 109
    :pswitch_2
    move-object v10, p2

    .line 110
    new-instance v2, Lg1/y0;

    .line 111
    .line 112
    iget-object p2, p0, Lg1/y0;->g:Ljava/lang/Object;

    .line 113
    .line 114
    move-object v3, p2

    .line 115
    check-cast v3, Lp3/x;

    .line 116
    .line 117
    iget-object p2, p0, Lg1/y0;->h:Ljava/lang/Object;

    .line 118
    .line 119
    move-object v4, p2

    .line 120
    check-cast v4, Lg1/d1;

    .line 121
    .line 122
    iget-object p2, p0, Lg1/y0;->i:Ljava/lang/Object;

    .line 123
    .line 124
    move-object v5, p2

    .line 125
    check-cast v5, Lf30/h;

    .line 126
    .line 127
    iget-object p2, p0, Lg1/y0;->j:Ljava/lang/Object;

    .line 128
    .line 129
    move-object v6, p2

    .line 130
    check-cast v6, Laa/o;

    .line 131
    .line 132
    iget-object p2, p0, Lg1/y0;->k:Ljava/lang/Object;

    .line 133
    .line 134
    move-object v7, p2

    .line 135
    check-cast v7, Lg1/x0;

    .line 136
    .line 137
    iget-object p2, p0, Lg1/y0;->l:Ljava/lang/Object;

    .line 138
    .line 139
    move-object v8, p2

    .line 140
    check-cast v8, Lg1/x0;

    .line 141
    .line 142
    iget-object p0, p0, Lg1/y0;->m:Ljava/lang/Object;

    .line 143
    .line 144
    move-object v9, p0

    .line 145
    check-cast v9, Lf20/f;

    .line 146
    .line 147
    const/4 v11, 0x0

    .line 148
    invoke-direct/range {v2 .. v11}, Lg1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 149
    .line 150
    .line 151
    iput-object p1, v2, Lg1/y0;->f:Ljava/lang/Object;

    .line 152
    .line 153
    return-object v2

    .line 154
    nop

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/y0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/y0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/y0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/y0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/y0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/y0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/y0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lg1/y0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lg1/y0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lg1/y0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lg1/y0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lg1/y0;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lg1/y0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lg1/y0;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    iget-object v6, v0, Lg1/y0;->l:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v7, v0, Lg1/y0;->m:Ljava/lang/Object;

    .line 14
    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    iget-object v1, v0, Lg1/y0;->k:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Luu/g;

    .line 21
    .line 22
    check-cast v7, Ll2/b1;

    .line 23
    .line 24
    check-cast v6, Ll2/b1;

    .line 25
    .line 26
    iget-object v8, v0, Lg1/y0;->h:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v8, Ll2/b1;

    .line 29
    .line 30
    iget-object v9, v0, Lg1/y0;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v9, Li91/r2;

    .line 33
    .line 34
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    iget v11, v0, Lg1/y0;->e:I

    .line 37
    .line 38
    const/4 v12, 0x0

    .line 39
    if-eqz v11, :cond_1

    .line 40
    .line 41
    if-ne v11, v5, :cond_0

    .line 42
    .line 43
    iget-object v0, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 44
    .line 45
    move-object v6, v0

    .line 46
    check-cast v6, Ll2/b1;

    .line 47
    .line 48
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v9}, Li91/r2;->c()Li91/s2;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    const/4 v11, -0x1

    .line 66
    if-nez v4, :cond_2

    .line 67
    .line 68
    move v4, v11

    .line 69
    goto :goto_0

    .line 70
    :cond_2
    sget-object v13, Ln70/l;->a:[I

    .line 71
    .line 72
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    aget v4, v13, v4

    .line 77
    .line 78
    :goto_0
    if-eq v4, v11, :cond_5

    .line 79
    .line 80
    if-eq v4, v5, :cond_3

    .line 81
    .line 82
    if-eq v4, v2, :cond_3

    .line 83
    .line 84
    goto/16 :goto_4

    .line 85
    .line 86
    :cond_3
    sget v2, Ln70/m;->a:F

    .line 87
    .line 88
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    check-cast v2, Li91/s2;

    .line 93
    .line 94
    invoke-virtual {v9}, Li91/r2;->c()Li91/s2;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    if-eq v2, v4, :cond_8

    .line 99
    .line 100
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-interface {v8, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    check-cast v2, Lcom/google/android/gms/maps/model/LatLng;

    .line 110
    .line 111
    if-eqz v2, :cond_8

    .line 112
    .line 113
    invoke-static {v2}, Ljp/wf;->c(Lcom/google/android/gms/maps/model/LatLng;)Lpv/g;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    iput-object v6, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 118
    .line 119
    iput v5, v0, Lg1/y0;->e:I

    .line 120
    .line 121
    const v4, 0x7fffffff

    .line 122
    .line 123
    .line 124
    invoke-virtual {v1, v2, v4, v0}, Luu/g;->b(Lpv/g;ILrx0/c;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    if-ne v0, v10, :cond_4

    .line 129
    .line 130
    move-object v3, v10

    .line 131
    goto/16 :goto_5

    .line 132
    .line 133
    :cond_4
    :goto_1
    sget v0, Ln70/m;->a:F

    .line 134
    .line 135
    invoke-interface {v6, v12}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_5
    sget v4, Ln70/m;->a:F

    .line 140
    .line 141
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    check-cast v4, Ljava/lang/Boolean;

    .line 146
    .line 147
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 148
    .line 149
    .line 150
    move-result v4

    .line 151
    if-nez v4, :cond_8

    .line 152
    .line 153
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 154
    .line 155
    invoke-interface {v8, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    iget-object v4, v0, Lg1/y0;->i:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v4, Ll2/t2;

    .line 161
    .line 162
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    check-cast v4, Ljava/lang/Integer;

    .line 167
    .line 168
    if-eqz v4, :cond_7

    .line 169
    .line 170
    iget-object v0, v0, Lg1/y0;->j:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v0, Lw3/j2;

    .line 173
    .line 174
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    new-instance v8, Landroid/graphics/Point;

    .line 179
    .line 180
    check-cast v0, Lw3/r1;

    .line 181
    .line 182
    invoke-virtual {v0}, Lw3/r1;->a()J

    .line 183
    .line 184
    .line 185
    move-result-wide v10

    .line 186
    const/16 v0, 0x20

    .line 187
    .line 188
    shr-long/2addr v10, v0

    .line 189
    long-to-int v0, v10

    .line 190
    div-int/2addr v0, v2

    .line 191
    div-int/2addr v4, v2

    .line 192
    invoke-direct {v8, v0, v4}, Landroid/graphics/Point;-><init>(II)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v1}, Luu/g;->c()Lqp/g;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    if-eqz v0, :cond_6

    .line 200
    .line 201
    invoke-virtual {v0}, Lqp/g;->c()Lj1/a;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    goto :goto_2

    .line 206
    :cond_6
    move-object v0, v12

    .line 207
    :goto_2
    if-eqz v0, :cond_7

    .line 208
    .line 209
    :try_start_0
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 210
    .line 211
    check-cast v0, Lrp/b;

    .line 212
    .line 213
    new-instance v1, Lyo/b;

    .line 214
    .line 215
    invoke-direct {v1, v8}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 219
    .line 220
    .line 221
    move-result-object v2

    .line 222
    invoke-static {v2, v1}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v0, v2, v5}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    sget-object v1, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 230
    .line 231
    invoke-static {v0, v1}, Lhp/j;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    move-object v12, v1

    .line 236
    check-cast v12, Lcom/google/android/gms/maps/model/LatLng;

    .line 237
    .line 238
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 239
    .line 240
    .line 241
    goto :goto_3

    .line 242
    :catch_0
    move-exception v0

    .line 243
    new-instance v1, La8/r0;

    .line 244
    .line 245
    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 246
    .line 247
    .line 248
    throw v1

    .line 249
    :cond_7
    :goto_3
    invoke-interface {v6, v12}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    :cond_8
    :goto_4
    invoke-virtual {v9}, Li91/r2;->c()Li91/s2;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    sget v1, Ln70/m;->a:F

    .line 257
    .line 258
    invoke-interface {v7, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 259
    .line 260
    .line 261
    :goto_5
    return-object v3

    .line 262
    :pswitch_0
    check-cast v6, Lhu/o0;

    .line 263
    .line 264
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 265
    .line 266
    iget v8, v0, Lg1/y0;->e:I

    .line 267
    .line 268
    const/4 v9, 0x3

    .line 269
    if-eqz v8, :cond_c

    .line 270
    .line 271
    if-eq v8, v5, :cond_b

    .line 272
    .line 273
    if-eq v8, v2, :cond_a

    .line 274
    .line 275
    if-ne v8, v9, :cond_9

    .line 276
    .line 277
    iget-object v1, v0, Lg1/y0;->k:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v1, Lku/j;

    .line 280
    .line 281
    iget-object v2, v0, Lg1/y0;->j:Ljava/lang/Object;

    .line 282
    .line 283
    check-cast v2, Lhu/j0;

    .line 284
    .line 285
    iget-object v4, v0, Lg1/y0;->i:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast v4, Lsr/f;

    .line 288
    .line 289
    iget-object v5, v0, Lg1/y0;->h:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v5, Lhu/l0;

    .line 292
    .line 293
    iget-object v6, v0, Lg1/y0;->g:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast v6, Lhu/o0;

    .line 296
    .line 297
    iget-object v0, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 298
    .line 299
    check-cast v0, Lhu/u;

    .line 300
    .line 301
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    move-object v7, v2

    .line 305
    move-object v2, v0

    .line 306
    move-object/from16 v0, p1

    .line 307
    .line 308
    goto :goto_9

    .line 309
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 310
    .line 311
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    throw v0

    .line 315
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 316
    .line 317
    .line 318
    move-object/from16 v2, p1

    .line 319
    .line 320
    goto :goto_7

    .line 321
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    move-object/from16 v4, p1

    .line 325
    .line 326
    goto :goto_6

    .line 327
    :cond_c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 328
    .line 329
    .line 330
    iput v5, v0, Lg1/y0;->e:I

    .line 331
    .line 332
    invoke-static {v6, v0}, Lhu/o0;->a(Lhu/o0;Lrx0/c;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v4

    .line 336
    if-ne v4, v1, :cond_d

    .line 337
    .line 338
    goto :goto_8

    .line 339
    :cond_d
    :goto_6
    check-cast v4, Ljava/lang/Boolean;

    .line 340
    .line 341
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 342
    .line 343
    .line 344
    move-result v4

    .line 345
    if-eqz v4, :cond_14

    .line 346
    .line 347
    iget-object v4, v6, Lhu/o0;->b:Lht/d;

    .line 348
    .line 349
    iput v2, v0, Lg1/y0;->e:I

    .line 350
    .line 351
    sget-object v2, Lhu/u;->c:Lhu/o;

    .line 352
    .line 353
    invoke-virtual {v2, v4, v0}, Lhu/o;->a(Lht/d;Lrx0/c;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v2

    .line 357
    if-ne v2, v1, :cond_e

    .line 358
    .line 359
    goto :goto_8

    .line 360
    :cond_e
    :goto_7
    check-cast v2, Lhu/u;

    .line 361
    .line 362
    sget-object v5, Lhu/l0;->a:Lhu/l0;

    .line 363
    .line 364
    iget-object v4, v6, Lhu/o0;->a:Lsr/f;

    .line 365
    .line 366
    check-cast v7, Lhu/j0;

    .line 367
    .line 368
    iget-object v8, v6, Lhu/o0;->c:Lku/j;

    .line 369
    .line 370
    sget-object v10, Liu/c;->a:Liu/c;

    .line 371
    .line 372
    iput-object v2, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 373
    .line 374
    iput-object v6, v0, Lg1/y0;->g:Ljava/lang/Object;

    .line 375
    .line 376
    iput-object v5, v0, Lg1/y0;->h:Ljava/lang/Object;

    .line 377
    .line 378
    iput-object v4, v0, Lg1/y0;->i:Ljava/lang/Object;

    .line 379
    .line 380
    iput-object v7, v0, Lg1/y0;->j:Ljava/lang/Object;

    .line 381
    .line 382
    iput-object v8, v0, Lg1/y0;->k:Ljava/lang/Object;

    .line 383
    .line 384
    iput v9, v0, Lg1/y0;->e:I

    .line 385
    .line 386
    invoke-virtual {v10, v0}, Liu/c;->b(Lrx0/c;)Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v0

    .line 390
    if-ne v0, v1, :cond_f

    .line 391
    .line 392
    :goto_8
    move-object v3, v1

    .line 393
    goto/16 :goto_e

    .line 394
    .line 395
    :cond_f
    move-object v1, v8

    .line 396
    :goto_9
    check-cast v0, Ljava/util/Map;

    .line 397
    .line 398
    iget-object v15, v2, Lhu/u;->a:Ljava/lang/String;

    .line 399
    .line 400
    iget-object v2, v2, Lhu/u;->b:Ljava/lang/String;

    .line 401
    .line 402
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 403
    .line 404
    .line 405
    const-string v5, "firebaseApp"

    .line 406
    .line 407
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 408
    .line 409
    .line 410
    const-string v5, "sessionDetails"

    .line 411
    .line 412
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 413
    .line 414
    .line 415
    const-string v5, "sessionsSettings"

    .line 416
    .line 417
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 418
    .line 419
    .line 420
    const-string v5, "subscribers"

    .line 421
    .line 422
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 423
    .line 424
    .line 425
    const-string v5, "firebaseAuthenticationToken"

    .line 426
    .line 427
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 428
    .line 429
    .line 430
    new-instance v5, Lhu/k0;

    .line 431
    .line 432
    sget-object v8, Lhu/m;->e:Lhu/m;

    .line 433
    .line 434
    new-instance v8, Lhu/q0;

    .line 435
    .line 436
    iget-object v9, v7, Lhu/j0;->a:Ljava/lang/String;

    .line 437
    .line 438
    iget-object v10, v7, Lhu/j0;->b:Ljava/lang/String;

    .line 439
    .line 440
    iget v11, v7, Lhu/j0;->c:I

    .line 441
    .line 442
    iget-wide v12, v7, Lhu/j0;->d:J

    .line 443
    .line 444
    new-instance v14, Lhu/k;

    .line 445
    .line 446
    sget-object v7, Liu/d;->e:Liu/d;

    .line 447
    .line 448
    invoke-interface {v0, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v7

    .line 452
    check-cast v7, Lms/i;

    .line 453
    .line 454
    if-nez v7, :cond_10

    .line 455
    .line 456
    sget-object v7, Lhu/j;->e:Lhu/j;

    .line 457
    .line 458
    :goto_a
    move-object/from16 v16, v1

    .line 459
    .line 460
    goto :goto_b

    .line 461
    :cond_10
    iget-object v7, v7, Lms/i;->a:Lh8/o;

    .line 462
    .line 463
    invoke-virtual {v7}, Lh8/o;->a()Z

    .line 464
    .line 465
    .line 466
    move-result v7

    .line 467
    if-eqz v7, :cond_11

    .line 468
    .line 469
    sget-object v7, Lhu/j;->f:Lhu/j;

    .line 470
    .line 471
    goto :goto_a

    .line 472
    :cond_11
    sget-object v7, Lhu/j;->g:Lhu/j;

    .line 473
    .line 474
    goto :goto_a

    .line 475
    :goto_b
    sget-object v1, Liu/d;->d:Liu/d;

    .line 476
    .line 477
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 478
    .line 479
    .line 480
    move-result-object v0

    .line 481
    check-cast v0, Lms/i;

    .line 482
    .line 483
    if-nez v0, :cond_12

    .line 484
    .line 485
    sget-object v0, Lhu/j;->e:Lhu/j;

    .line 486
    .line 487
    :goto_c
    move-object/from16 p0, v2

    .line 488
    .line 489
    goto :goto_d

    .line 490
    :cond_12
    iget-object v0, v0, Lms/i;->a:Lh8/o;

    .line 491
    .line 492
    invoke-virtual {v0}, Lh8/o;->a()Z

    .line 493
    .line 494
    .line 495
    move-result v0

    .line 496
    if-eqz v0, :cond_13

    .line 497
    .line 498
    sget-object v0, Lhu/j;->f:Lhu/j;

    .line 499
    .line 500
    goto :goto_c

    .line 501
    :cond_13
    sget-object v0, Lhu/j;->g:Lhu/j;

    .line 502
    .line 503
    goto :goto_c

    .line 504
    :goto_d
    invoke-virtual/range {v16 .. v16}, Lku/j;->a()D

    .line 505
    .line 506
    .line 507
    move-result-wide v1

    .line 508
    invoke-direct {v14, v7, v0, v1, v2}, Lhu/k;-><init>(Lhu/j;Lhu/j;D)V

    .line 509
    .line 510
    .line 511
    move-object/from16 v16, p0

    .line 512
    .line 513
    invoke-direct/range {v8 .. v16}, Lhu/q0;-><init>(Ljava/lang/String;Ljava/lang/String;IJLhu/k;Ljava/lang/String;Ljava/lang/String;)V

    .line 514
    .line 515
    .line 516
    invoke-static {v4}, Lhu/l0;->a(Lsr/f;)Lhu/b;

    .line 517
    .line 518
    .line 519
    move-result-object v0

    .line 520
    invoke-direct {v5, v8, v0}, Lhu/k0;-><init>(Lhu/q0;Lhu/b;)V

    .line 521
    .line 522
    .line 523
    sget v0, Lhu/o0;->g:I

    .line 524
    .line 525
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 526
    .line 527
    .line 528
    const-string v1, "FirebaseSessions"

    .line 529
    .line 530
    :try_start_1
    iget-object v0, v6, Lhu/o0;->d:Lhu/l;

    .line 531
    .line 532
    invoke-virtual {v0, v5}, Lhu/l;->a(Lhu/k0;)V

    .line 533
    .line 534
    .line 535
    const-string v0, "Successfully logged Session Start event."

    .line 536
    .line 537
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    .line 538
    .line 539
    .line 540
    goto :goto_e

    .line 541
    :catch_1
    move-exception v0

    .line 542
    const-string v2, "Error logging Session Start event to DataTransport: "

    .line 543
    .line 544
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 545
    .line 546
    .line 547
    :cond_14
    :goto_e
    return-object v3

    .line 548
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 549
    .line 550
    iget v2, v0, Lg1/y0;->e:I

    .line 551
    .line 552
    if-eqz v2, :cond_16

    .line 553
    .line 554
    if-ne v2, v5, :cond_15

    .line 555
    .line 556
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 557
    .line 558
    .line 559
    goto :goto_f

    .line 560
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 561
    .line 562
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 563
    .line 564
    .line 565
    throw v0

    .line 566
    :cond_16
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 567
    .line 568
    .line 569
    iget-object v2, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 570
    .line 571
    move-object/from16 v17, v2

    .line 572
    .line 573
    check-cast v17, Lvy0/b0;

    .line 574
    .line 575
    new-instance v11, Lkotlin/jvm/internal/e0;

    .line 576
    .line 577
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 578
    .line 579
    .line 580
    iget-object v2, v0, Lg1/y0;->g:Ljava/lang/Object;

    .line 581
    .line 582
    move-object v10, v2

    .line 583
    check-cast v10, Ll2/y1;

    .line 584
    .line 585
    iget-wide v8, v10, Ll2/y1;->a:J

    .line 586
    .line 587
    iput-wide v8, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 588
    .line 589
    iget-object v2, v10, Ll2/y1;->u:Lyy0/c2;

    .line 590
    .line 591
    new-instance v8, Lh7/s;

    .line 592
    .line 593
    iget-object v4, v0, Lg1/y0;->h:Ljava/lang/Object;

    .line 594
    .line 595
    move-object v9, v4

    .line 596
    check-cast v9, La7/n;

    .line 597
    .line 598
    iget-object v4, v0, Lg1/y0;->i:Ljava/lang/Object;

    .line 599
    .line 600
    move-object v12, v4

    .line 601
    check-cast v12, Lyy0/c2;

    .line 602
    .line 603
    iget-object v4, v0, Lg1/y0;->j:Ljava/lang/Object;

    .line 604
    .line 605
    move-object v13, v4

    .line 606
    check-cast v13, Landroid/content/Context;

    .line 607
    .line 608
    iget-object v4, v0, Lg1/y0;->k:Ljava/lang/Object;

    .line 609
    .line 610
    move-object v14, v4

    .line 611
    check-cast v14, La7/q1;

    .line 612
    .line 613
    move-object v15, v6

    .line 614
    check-cast v15, Lh7/a0;

    .line 615
    .line 616
    move-object/from16 v16, v7

    .line 617
    .line 618
    check-cast v16, Lh7/x;

    .line 619
    .line 620
    const/16 v18, 0x0

    .line 621
    .line 622
    invoke-direct/range {v8 .. v18}, Lh7/s;-><init>(La7/n;Ll2/y1;Lkotlin/jvm/internal/e0;Lyy0/c2;Landroid/content/Context;La7/q1;Lh7/a0;Lh7/x;Lvy0/b0;Lkotlin/coroutines/Continuation;)V

    .line 623
    .line 624
    .line 625
    iput v5, v0, Lg1/y0;->e:I

    .line 626
    .line 627
    invoke-static {v8, v0, v2}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 628
    .line 629
    .line 630
    move-result-object v0

    .line 631
    if-ne v0, v1, :cond_17

    .line 632
    .line 633
    move-object v3, v1

    .line 634
    :cond_17
    :goto_f
    return-object v3

    .line 635
    :pswitch_2
    iget-object v1, v0, Lg1/y0;->h:Ljava/lang/Object;

    .line 636
    .line 637
    check-cast v1, Lg1/d1;

    .line 638
    .line 639
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 640
    .line 641
    iget v8, v0, Lg1/y0;->e:I

    .line 642
    .line 643
    if-eqz v8, :cond_19

    .line 644
    .line 645
    if-ne v8, v5, :cond_18

    .line 646
    .line 647
    iget-object v0, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 648
    .line 649
    move-object v2, v0

    .line 650
    check-cast v2, Lvy0/b0;

    .line 651
    .line 652
    :try_start_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_2

    .line 653
    .line 654
    .line 655
    goto :goto_13

    .line 656
    :catch_2
    move-exception v0

    .line 657
    goto :goto_12

    .line 658
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 659
    .line 660
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 661
    .line 662
    .line 663
    throw v0

    .line 664
    :cond_19
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 665
    .line 666
    .line 667
    iget-object v4, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 668
    .line 669
    check-cast v4, Lvy0/b0;

    .line 670
    .line 671
    :try_start_3
    iget-object v8, v0, Lg1/y0;->g:Ljava/lang/Object;

    .line 672
    .line 673
    check-cast v8, Lp3/x;

    .line 674
    .line 675
    iget-object v12, v1, Lg1/d1;->t:Lg1/w1;

    .line 676
    .line 677
    iget-object v9, v0, Lg1/y0;->i:Ljava/lang/Object;

    .line 678
    .line 679
    move-object v13, v9

    .line 680
    check-cast v13, Lf30/h;

    .line 681
    .line 682
    iget-object v9, v0, Lg1/y0;->j:Ljava/lang/Object;

    .line 683
    .line 684
    move-object/from16 v16, v9

    .line 685
    .line 686
    check-cast v16, Laa/o;

    .line 687
    .line 688
    iget-object v9, v0, Lg1/y0;->k:Ljava/lang/Object;

    .line 689
    .line 690
    move-object v15, v9

    .line 691
    check-cast v15, Lg1/x0;

    .line 692
    .line 693
    move-object v10, v6

    .line 694
    check-cast v10, Lg1/x0;

    .line 695
    .line 696
    move-object v14, v7

    .line 697
    check-cast v14, Lf20/f;

    .line 698
    .line 699
    iput-object v4, v0, Lg1/y0;->f:Ljava/lang/Object;

    .line 700
    .line 701
    iput v5, v0, Lg1/y0;->e:I

    .line 702
    .line 703
    sget v5, Lg1/w0;->a:F

    .line 704
    .line 705
    new-instance v11, Lkotlin/jvm/internal/e0;

    .line 706
    .line 707
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 708
    .line 709
    .line 710
    new-instance v9, Lg1/q0;

    .line 711
    .line 712
    const/16 v17, 0x0

    .line 713
    .line 714
    invoke-direct/range {v9 .. v17}, Lg1/q0;-><init>(Lay0/a;Lkotlin/jvm/internal/e0;Lg1/w1;Lay0/o;Lay0/n;Lay0/a;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 715
    .line 716
    .line 717
    invoke-static {v8, v9, v0}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 718
    .line 719
    .line 720
    move-result-object v0
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_3

    .line 721
    if-ne v0, v2, :cond_1a

    .line 722
    .line 723
    goto :goto_10

    .line 724
    :cond_1a
    move-object v0, v3

    .line 725
    :goto_10
    if-ne v0, v2, :cond_1c

    .line 726
    .line 727
    move-object v3, v2

    .line 728
    goto :goto_13

    .line 729
    :goto_11
    move-object v2, v4

    .line 730
    goto :goto_12

    .line 731
    :catch_3
    move-exception v0

    .line 732
    goto :goto_11

    .line 733
    :goto_12
    iget-object v1, v1, Lg1/d1;->x:Lxy0/j;

    .line 734
    .line 735
    if-eqz v1, :cond_1b

    .line 736
    .line 737
    sget-object v4, Lg1/g0;->a:Lg1/g0;

    .line 738
    .line 739
    invoke-interface {v1, v4}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 740
    .line 741
    .line 742
    :cond_1b
    invoke-static {v2}, Lvy0/e0;->B(Lvy0/b0;)Z

    .line 743
    .line 744
    .line 745
    move-result v1

    .line 746
    if-eqz v1, :cond_1d

    .line 747
    .line 748
    :cond_1c
    :goto_13
    return-object v3

    .line 749
    :cond_1d
    throw v0

    .line 750
    nop

    .line 751
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.class public final Le2/f0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:J

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Le2/f0;->d:I

    iput-wide p1, p0, Le2/f0;->f:J

    iput-object p3, p0, Le2/f0;->g:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p5, p0, Le2/f0;->d:I

    iput-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    iput-wide p2, p0, Le2/f0;->f:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Le2/f0;->d:I

    .line 3
    iput-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Le2/f0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Le2/f0;

    .line 7
    .line 8
    iget-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    check-cast v2, Lx21/y;

    .line 12
    .line 13
    iget-wide v3, p0, Le2/f0;->f:J

    .line 14
    .line 15
    const/16 v6, 0x8

    .line 16
    .line 17
    move-object v5, p2

    .line 18
    invoke-direct/range {v1 .. v6}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    move-object v6, p2

    .line 23
    new-instance v2, Le2/f0;

    .line 24
    .line 25
    iget-wide v3, p0, Le2/f0;->f:J

    .line 26
    .line 27
    iget-object p0, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 28
    .line 29
    move-object v5, p0

    .line 30
    check-cast v5, Lw40/s;

    .line 31
    .line 32
    const/4 v7, 0x7

    .line 33
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    return-object v2

    .line 37
    :pswitch_1
    move-object v6, p2

    .line 38
    new-instance v2, Le2/f0;

    .line 39
    .line 40
    iget-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 41
    .line 42
    move-object v3, p1

    .line 43
    check-cast v3, Lw4/g;

    .line 44
    .line 45
    iget-wide v4, p0, Le2/f0;->f:J

    .line 46
    .line 47
    const/4 v7, 0x6

    .line 48
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    return-object v2

    .line 52
    :pswitch_2
    move-object v6, p2

    .line 53
    new-instance v2, Le2/f0;

    .line 54
    .line 55
    iget-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v3, p1

    .line 58
    check-cast v3, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 59
    .line 60
    iget-wide v4, p0, Le2/f0;->f:J

    .line 61
    .line 62
    const/4 v7, 0x5

    .line 63
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 64
    .line 65
    .line 66
    return-object v2

    .line 67
    :pswitch_3
    move-object v6, p2

    .line 68
    new-instance v2, Le2/f0;

    .line 69
    .line 70
    iget-wide v3, p0, Le2/f0;->f:J

    .line 71
    .line 72
    iget-object p0, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 73
    .line 74
    move-object v5, p0

    .line 75
    check-cast v5, Lp3/i0;

    .line 76
    .line 77
    const/4 v7, 0x4

    .line 78
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 79
    .line 80
    .line 81
    return-object v2

    .line 82
    :pswitch_4
    move-object v6, p2

    .line 83
    new-instance v2, Le2/f0;

    .line 84
    .line 85
    iget-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 86
    .line 87
    move-object v3, p1

    .line 88
    check-cast v3, Lkn/p0;

    .line 89
    .line 90
    iget-wide v4, p0, Le2/f0;->f:J

    .line 91
    .line 92
    const/4 v7, 0x3

    .line 93
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 94
    .line 95
    .line 96
    return-object v2

    .line 97
    :pswitch_5
    move-object v6, p2

    .line 98
    new-instance p2, Le2/f0;

    .line 99
    .line 100
    iget-object p0, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 103
    .line 104
    invoke-direct {p2, p0, v6}, Le2/f0;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)V

    .line 105
    .line 106
    .line 107
    check-cast p1, Lmy0/c;

    .line 108
    .line 109
    iget-wide p0, p1, Lmy0/c;->d:J

    .line 110
    .line 111
    iput-wide p0, p2, Le2/f0;->f:J

    .line 112
    .line 113
    return-object p2

    .line 114
    :pswitch_6
    move-object v6, p2

    .line 115
    new-instance v2, Le2/f0;

    .line 116
    .line 117
    iget-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 118
    .line 119
    move-object v3, p1

    .line 120
    check-cast v3, Lg1/m;

    .line 121
    .line 122
    iget-wide v4, p0, Le2/f0;->f:J

    .line 123
    .line 124
    const/4 v7, 0x1

    .line 125
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 126
    .line 127
    .line 128
    return-object v2

    .line 129
    :pswitch_7
    move-object v6, p2

    .line 130
    new-instance v2, Le2/f0;

    .line 131
    .line 132
    iget-object p1, p0, Le2/f0;->g:Ljava/lang/Object;

    .line 133
    .line 134
    move-object v3, p1

    .line 135
    check-cast v3, Lc1/c;

    .line 136
    .line 137
    iget-wide v4, p0, Le2/f0;->f:J

    .line 138
    .line 139
    const/4 v7, 0x0

    .line 140
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 141
    .line 142
    .line 143
    return-object v2

    .line 144
    nop

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Le2/f0;->d:I

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
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Le2/f0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Le2/f0;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Le2/f0;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Le2/f0;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lvy0/b0;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Le2/f0;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_4
    check-cast p1, Lvy0/b0;

    .line 92
    .line 93
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 94
    .line 95
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Le2/f0;

    .line 100
    .line 101
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :pswitch_5
    check-cast p1, Lmy0/c;

    .line 109
    .line 110
    iget-wide v0, p1, Lmy0/c;->d:J

    .line 111
    .line 112
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 113
    .line 114
    new-instance p1, Lmy0/c;

    .line 115
    .line 116
    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    check-cast p0, Le2/f0;

    .line 124
    .line 125
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0

    .line 132
    :pswitch_6
    check-cast p1, Lvy0/b0;

    .line 133
    .line 134
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 135
    .line 136
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    check-cast p0, Le2/f0;

    .line 141
    .line 142
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 143
    .line 144
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0

    .line 149
    :pswitch_7
    check-cast p1, Lvy0/b0;

    .line 150
    .line 151
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 152
    .line 153
    invoke-virtual {p0, p1, p2}, Le2/f0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    check-cast p0, Le2/f0;

    .line 158
    .line 159
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    invoke-virtual {p0, p1}, Le2/f0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0

    .line 166
    nop

    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    iget v0, v5, Le2/f0;->d:I

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 9
    .line 10
    iget-object v3, v5, Le2/f0;->g:Ljava/lang/Object;

    .line 11
    .line 12
    const/4 v4, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    move-object v8, v3

    .line 17
    check-cast v8, Lx21/y;

    .line 18
    .line 19
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v0, v5, Le2/f0;->e:I

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    if-eq v0, v4, :cond_1

    .line 26
    .line 27
    if-ne v0, v1, :cond_0

    .line 28
    .line 29
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    goto :goto_2

    .line 33
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, v8, Lx21/y;->t:Lc1/c;

    .line 47
    .line 48
    iget-wide v2, v5, Le2/f0;->f:J

    .line 49
    .line 50
    new-instance v6, Ld3/b;

    .line 51
    .line 52
    invoke-direct {v6, v2, v3}, Ld3/b;-><init>(J)V

    .line 53
    .line 54
    .line 55
    iput v4, v5, Le2/f0;->e:I

    .line 56
    .line 57
    invoke-virtual {v0, v6, v5}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    if-ne v0, v9, :cond_3

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    :goto_0
    iget-object v0, v8, Lx21/y;->t:Lc1/c;

    .line 65
    .line 66
    new-instance v2, Ld3/b;

    .line 67
    .line 68
    const-wide/16 v10, 0x0

    .line 69
    .line 70
    invoke-direct {v2, v10, v11}, Ld3/b;-><init>(J)V

    .line 71
    .line 72
    .line 73
    const/high16 v3, 0x3f000000    # 0.5f

    .line 74
    .line 75
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    int-to-long v10, v6

    .line 80
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    int-to-long v12, v3

    .line 85
    const/16 v3, 0x20

    .line 86
    .line 87
    shl-long/2addr v10, v3

    .line 88
    const-wide v14, 0xffffffffL

    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    and-long/2addr v12, v14

    .line 94
    or-long/2addr v10, v12

    .line 95
    new-instance v3, Ld3/b;

    .line 96
    .line 97
    invoke-direct {v3, v10, v11}, Ld3/b;-><init>(J)V

    .line 98
    .line 99
    .line 100
    const/4 v6, 0x0

    .line 101
    const/high16 v10, 0x43c80000    # 400.0f

    .line 102
    .line 103
    invoke-static {v6, v10, v3, v4}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    iput v1, v5, Le2/f0;->e:I

    .line 108
    .line 109
    move-object v1, v2

    .line 110
    move-object v2, v3

    .line 111
    const/4 v3, 0x0

    .line 112
    const/4 v4, 0x0

    .line 113
    const/16 v6, 0xc

    .line 114
    .line 115
    invoke-static/range {v0 .. v6}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    if-ne v0, v9, :cond_4

    .line 120
    .line 121
    :goto_1
    move-object v7, v9

    .line 122
    goto :goto_3

    .line 123
    :cond_4
    :goto_2
    iget-object v0, v8, Lx21/y;->s:Ll2/j1;

    .line 124
    .line 125
    const/4 v1, 0x0

    .line 126
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    :goto_3
    return-object v7

    .line 130
    :pswitch_0
    check-cast v3, Lw40/s;

    .line 131
    .line 132
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 133
    .line 134
    iget v6, v5, Le2/f0;->e:I

    .line 135
    .line 136
    if-eqz v6, :cond_7

    .line 137
    .line 138
    if-eq v6, v4, :cond_6

    .line 139
    .line 140
    if-ne v6, v1, :cond_5

    .line 141
    .line 142
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 147
    .line 148
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    throw v0

    .line 152
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    move-object/from16 v2, p1

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    sget-object v2, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 162
    .line 163
    invoke-static {v2}, Ljava/time/OffsetDateTime;->now(Ljava/time/ZoneId;)Ljava/time/OffsetDateTime;

    .line 164
    .line 165
    .line 166
    move-result-object v2

    .line 167
    iget-wide v8, v5, Le2/f0;->f:J

    .line 168
    .line 169
    sget v6, Lmy0/c;->g:I

    .line 170
    .line 171
    sget-object v6, Lmy0/e;->h:Lmy0/e;

    .line 172
    .line 173
    invoke-static {v8, v9, v6}, Lmy0/c;->n(JLmy0/e;)J

    .line 174
    .line 175
    .line 176
    move-result-wide v8

    .line 177
    sget-object v6, Ljava/time/temporal/ChronoUnit;->SECONDS:Ljava/time/temporal/ChronoUnit;

    .line 178
    .line 179
    invoke-virtual {v2, v8, v9, v6}, Ljava/time/OffsetDateTime;->plus(JLjava/time/temporal/TemporalUnit;)Ljava/time/OffsetDateTime;

    .line 180
    .line 181
    .line 182
    move-result-object v14

    .line 183
    iget-object v2, v3, Lw40/s;->l:Lu40/g;

    .line 184
    .line 185
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 186
    .line 187
    .line 188
    move-result-object v6

    .line 189
    check-cast v6, Lw40/n;

    .line 190
    .line 191
    iget-object v11, v6, Lw40/n;->c:Ljava/lang/String;

    .line 192
    .line 193
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 194
    .line 195
    .line 196
    move-result-object v6

    .line 197
    check-cast v6, Lw40/n;

    .line 198
    .line 199
    iget-object v13, v6, Lw40/n;->j:Ljava/lang/String;

    .line 200
    .line 201
    invoke-static {v14}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    check-cast v6, Lw40/n;

    .line 209
    .line 210
    iget-object v12, v6, Lw40/n;->u:Ljava/lang/String;

    .line 211
    .line 212
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 213
    .line 214
    .line 215
    move-result-object v6

    .line 216
    check-cast v6, Lw40/n;

    .line 217
    .line 218
    iget-boolean v15, v6, Lw40/n;->v:Z

    .line 219
    .line 220
    new-instance v10, Lu40/e;

    .line 221
    .line 222
    invoke-direct/range {v10 .. v15}, Lu40/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Z)V

    .line 223
    .line 224
    .line 225
    iput v4, v5, Le2/f0;->e:I

    .line 226
    .line 227
    invoke-virtual {v2, v10, v5}, Lu40/g;->b(Lu40/e;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    if-ne v2, v0, :cond_8

    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_8
    :goto_4
    check-cast v2, Lyy0/i;

    .line 235
    .line 236
    new-instance v6, Lw40/r;

    .line 237
    .line 238
    invoke-direct {v6, v3, v4}, Lw40/r;-><init>(Lw40/s;I)V

    .line 239
    .line 240
    .line 241
    iput v1, v5, Le2/f0;->e:I

    .line 242
    .line 243
    invoke-interface {v2, v6, v5}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v1

    .line 247
    if-ne v1, v0, :cond_9

    .line 248
    .line 249
    :goto_5
    move-object v7, v0

    .line 250
    :cond_9
    :goto_6
    return-object v7

    .line 251
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 252
    .line 253
    iget v1, v5, Le2/f0;->e:I

    .line 254
    .line 255
    if-eqz v1, :cond_b

    .line 256
    .line 257
    if-ne v1, v4, :cond_a

    .line 258
    .line 259
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    goto :goto_7

    .line 263
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 264
    .line 265
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    throw v0

    .line 269
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 270
    .line 271
    .line 272
    check-cast v3, Lw4/g;

    .line 273
    .line 274
    iget-object v1, v3, Lw4/g;->d:Lo3/d;

    .line 275
    .line 276
    iget-wide v2, v5, Le2/f0;->f:J

    .line 277
    .line 278
    iput v4, v5, Le2/f0;->e:I

    .line 279
    .line 280
    invoke-virtual {v1, v2, v3, v5}, Lo3/d;->b(JLrx0/c;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v1

    .line 284
    if-ne v1, v0, :cond_c

    .line 285
    .line 286
    move-object v7, v0

    .line 287
    :cond_c
    :goto_7
    return-object v7

    .line 288
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 289
    .line 290
    iget v1, v5, Le2/f0;->e:I

    .line 291
    .line 292
    if-eqz v1, :cond_e

    .line 293
    .line 294
    if-ne v1, v4, :cond_d

    .line 295
    .line 296
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    goto :goto_8

    .line 300
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 301
    .line 302
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    throw v0

    .line 306
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    check-cast v3, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 310
    .line 311
    iget-object v1, v3, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->i:Ljava/lang/Object;

    .line 312
    .line 313
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    check-cast v1, Lo40/a0;

    .line 318
    .line 319
    iget-wide v2, v5, Le2/f0;->f:J

    .line 320
    .line 321
    long-to-int v2, v2

    .line 322
    sget v3, Lmy0/c;->g:I

    .line 323
    .line 324
    sget-object v3, Lmy0/e;->h:Lmy0/e;

    .line 325
    .line 326
    invoke-static {v4, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 327
    .line 328
    .line 329
    move-result-wide v8

    .line 330
    invoke-static {v8, v9}, Lmy0/c;->e(J)J

    .line 331
    .line 332
    .line 333
    move-result-wide v8

    .line 334
    long-to-int v3, v8

    .line 335
    div-int/2addr v2, v3

    .line 336
    iput v4, v5, Le2/f0;->e:I

    .line 337
    .line 338
    invoke-virtual {v1, v2, v5}, Lo40/a0;->b(ILkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v1

    .line 342
    if-ne v1, v0, :cond_f

    .line 343
    .line 344
    move-object v7, v0

    .line 345
    :cond_f
    :goto_8
    return-object v7

    .line 346
    :pswitch_3
    iget-wide v8, v5, Le2/f0;->f:J

    .line 347
    .line 348
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 349
    .line 350
    iget v6, v5, Le2/f0;->e:I

    .line 351
    .line 352
    const-wide/16 v10, 0x8

    .line 353
    .line 354
    if-eqz v6, :cond_12

    .line 355
    .line 356
    if-eq v6, v4, :cond_11

    .line 357
    .line 358
    if-ne v6, v1, :cond_10

    .line 359
    .line 360
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 361
    .line 362
    .line 363
    goto :goto_b

    .line 364
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 365
    .line 366
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    throw v0

    .line 370
    :cond_11
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 371
    .line 372
    .line 373
    goto :goto_9

    .line 374
    :cond_12
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 375
    .line 376
    .line 377
    sub-long v12, v8, v10

    .line 378
    .line 379
    iput v4, v5, Le2/f0;->e:I

    .line 380
    .line 381
    invoke-static {v12, v13, v5}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v2

    .line 385
    if-ne v2, v0, :cond_13

    .line 386
    .line 387
    goto :goto_a

    .line 388
    :cond_13
    :goto_9
    iput v1, v5, Le2/f0;->e:I

    .line 389
    .line 390
    invoke-static {v10, v11, v5}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v1

    .line 394
    if-ne v1, v0, :cond_14

    .line 395
    .line 396
    :goto_a
    move-object v7, v0

    .line 397
    goto :goto_c

    .line 398
    :cond_14
    :goto_b
    check-cast v3, Lp3/i0;

    .line 399
    .line 400
    iget-object v0, v3, Lp3/i0;->f:Lvy0/l;

    .line 401
    .line 402
    if-eqz v0, :cond_15

    .line 403
    .line 404
    new-instance v1, Lp3/n;

    .line 405
    .line 406
    invoke-direct {v1, v8, v9}, Lp3/n;-><init>(J)V

    .line 407
    .line 408
    .line 409
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 410
    .line 411
    .line 412
    move-result-object v1

    .line 413
    invoke-virtual {v0, v1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 414
    .line 415
    .line 416
    :cond_15
    :goto_c
    return-object v7

    .line 417
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 418
    .line 419
    iget v1, v5, Le2/f0;->e:I

    .line 420
    .line 421
    if-eqz v1, :cond_17

    .line 422
    .line 423
    if-ne v1, v4, :cond_16

    .line 424
    .line 425
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 426
    .line 427
    .line 428
    goto :goto_d

    .line 429
    :cond_16
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 430
    .line 431
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 432
    .line 433
    .line 434
    throw v0

    .line 435
    :cond_17
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 436
    .line 437
    .line 438
    check-cast v3, Lkn/p0;

    .line 439
    .line 440
    iget-object v1, v3, Lkn/p0;->d:Lkn/c0;

    .line 441
    .line 442
    iget-wide v2, v5, Le2/f0;->f:J

    .line 443
    .line 444
    invoke-static {v2, v3}, Ld3/b;->f(J)F

    .line 445
    .line 446
    .line 447
    move-result v2

    .line 448
    iput v4, v5, Le2/f0;->e:I

    .line 449
    .line 450
    invoke-virtual {v1, v2, v5}, Lkn/c0;->a(FLrx0/i;)Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    move-result-object v1

    .line 454
    if-ne v1, v0, :cond_18

    .line 455
    .line 456
    move-object v7, v0

    .line 457
    :cond_18
    :goto_d
    return-object v7

    .line 458
    :pswitch_5
    iget-wide v0, v5, Le2/f0;->f:J

    .line 459
    .line 460
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 461
    .line 462
    iget v8, v5, Le2/f0;->e:I

    .line 463
    .line 464
    if-eqz v8, :cond_1a

    .line 465
    .line 466
    if-ne v8, v4, :cond_19

    .line 467
    .line 468
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    goto :goto_e

    .line 472
    :cond_19
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 473
    .line 474
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 475
    .line 476
    .line 477
    throw v0

    .line 478
    :cond_1a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 479
    .line 480
    .line 481
    check-cast v3, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 482
    .line 483
    invoke-static {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->access$get_sendDurations$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/i1;

    .line 484
    .line 485
    .line 486
    move-result-object v2

    .line 487
    new-instance v3, Lmy0/c;

    .line 488
    .line 489
    invoke-direct {v3, v0, v1}, Lmy0/c;-><init>(J)V

    .line 490
    .line 491
    .line 492
    iput-wide v0, v5, Le2/f0;->f:J

    .line 493
    .line 494
    iput v4, v5, Le2/f0;->e:I

    .line 495
    .line 496
    invoke-interface {v2, v3, v5}, Lyy0/i1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v0

    .line 500
    if-ne v0, v6, :cond_1b

    .line 501
    .line 502
    move-object v7, v6

    .line 503
    :cond_1b
    :goto_e
    return-object v7

    .line 504
    :pswitch_6
    check-cast v3, Lg1/m;

    .line 505
    .line 506
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 507
    .line 508
    iget v6, v5, Le2/f0;->e:I

    .line 509
    .line 510
    if-eqz v6, :cond_1e

    .line 511
    .line 512
    if-eq v6, v4, :cond_1d

    .line 513
    .line 514
    if-ne v6, v1, :cond_1c

    .line 515
    .line 516
    goto :goto_f

    .line 517
    :cond_1c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 518
    .line 519
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 520
    .line 521
    .line 522
    throw v0

    .line 523
    :cond_1d
    :goto_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 524
    .line 525
    .line 526
    goto :goto_13

    .line 527
    :cond_1e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 528
    .line 529
    .line 530
    iget-wide v1, v5, Le2/f0;->f:J

    .line 531
    .line 532
    invoke-virtual {v3}, Lg1/m;->k1()Z

    .line 533
    .line 534
    .line 535
    move-result v6

    .line 536
    if-eqz v6, :cond_1f

    .line 537
    .line 538
    const/high16 v6, -0x40800000    # -1.0f

    .line 539
    .line 540
    :goto_10
    invoke-static {v1, v2, v6}, Lt4/q;->f(JF)J

    .line 541
    .line 542
    .line 543
    move-result-wide v1

    .line 544
    goto :goto_11

    .line 545
    :cond_1f
    const/high16 v6, 0x3f800000    # 1.0f

    .line 546
    .line 547
    goto :goto_10

    .line 548
    :goto_11
    iget-object v6, v3, Lg1/m;->D:Lg1/w1;

    .line 549
    .line 550
    sget-object v8, Lg1/w1;->d:Lg1/w1;

    .line 551
    .line 552
    if-ne v6, v8, :cond_20

    .line 553
    .line 554
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 555
    .line 556
    .line 557
    move-result v1

    .line 558
    goto :goto_12

    .line 559
    :cond_20
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 560
    .line 561
    .line 562
    move-result v1

    .line 563
    :goto_12
    iput v4, v5, Le2/f0;->e:I

    .line 564
    .line 565
    invoke-static {v3, v1, v5}, Lg1/m;->j1(Lg1/m;FLrx0/c;)Ljava/lang/Object;

    .line 566
    .line 567
    .line 568
    move-result-object v1

    .line 569
    if-ne v1, v0, :cond_21

    .line 570
    .line 571
    move-object v7, v0

    .line 572
    :cond_21
    :goto_13
    return-object v7

    .line 573
    :pswitch_7
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 574
    .line 575
    iget v0, v5, Le2/f0;->e:I

    .line 576
    .line 577
    if-eqz v0, :cond_23

    .line 578
    .line 579
    if-ne v0, v4, :cond_22

    .line 580
    .line 581
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 582
    .line 583
    .line 584
    goto :goto_14

    .line 585
    :cond_22
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 586
    .line 587
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 588
    .line 589
    .line 590
    throw v0

    .line 591
    :cond_23
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 592
    .line 593
    .line 594
    move-object v0, v3

    .line 595
    check-cast v0, Lc1/c;

    .line 596
    .line 597
    iget-wide v1, v5, Le2/f0;->f:J

    .line 598
    .line 599
    new-instance v3, Ld3/b;

    .line 600
    .line 601
    invoke-direct {v3, v1, v2}, Ld3/b;-><init>(J)V

    .line 602
    .line 603
    .line 604
    sget-object v2, Le2/g0;->d:Lc1/f1;

    .line 605
    .line 606
    iput v4, v5, Le2/f0;->e:I

    .line 607
    .line 608
    move-object v1, v3

    .line 609
    const/4 v3, 0x0

    .line 610
    const/4 v4, 0x0

    .line 611
    const/16 v6, 0xc

    .line 612
    .line 613
    invoke-static/range {v0 .. v6}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 614
    .line 615
    .line 616
    move-result-object v0

    .line 617
    if-ne v0, v8, :cond_24

    .line 618
    .line 619
    move-object v7, v8

    .line 620
    :cond_24
    :goto_14
    return-object v7

    .line 621
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

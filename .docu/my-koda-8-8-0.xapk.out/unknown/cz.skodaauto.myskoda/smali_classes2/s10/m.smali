.class public final Ls10/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ls10/s;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Ls10/s;)V
    .locals 0

    .line 1
    iput p1, p0, Ls10/m;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Ls10/m;->f:Ls10/s;

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
    .locals 1

    .line 1
    iget p1, p0, Ls10/m;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ls10/m;

    .line 7
    .line 8
    iget-object p0, p0, Ls10/m;->f:Ls10/s;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, v0, p2, p0}, Ls10/m;-><init>(ILkotlin/coroutines/Continuation;Ls10/s;)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ls10/m;

    .line 16
    .line 17
    iget-object p0, p0, Ls10/m;->f:Ls10/s;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, v0, p2, p0}, Ls10/m;-><init>(ILkotlin/coroutines/Continuation;Ls10/s;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ls10/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Ls10/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ls10/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ls10/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ls10/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ls10/m;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ls10/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Ls10/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ls10/m;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    if-ne v1, v3, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    move-object v0, v2

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iput v3, p0, Ls10/m;->e:I

    .line 34
    .line 35
    iget-object p1, p0, Ls10/m;->f:Ls10/s;

    .line 36
    .line 37
    iget-object v1, p1, Ls10/s;->k:Lq10/h;

    .line 38
    .line 39
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lyy0/i;

    .line 44
    .line 45
    new-instance v3, Ls10/r;

    .line 46
    .line 47
    const/4 v4, 0x0

    .line 48
    const/4 v5, 0x0

    .line 49
    invoke-direct {v3, v5, v4, p1}, Ls10/r;-><init>(ILkotlin/coroutines/Continuation;Ls10/s;)V

    .line 50
    .line 51
    .line 52
    invoke-static {v1, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    if-ne p0, v0, :cond_3

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    move-object p0, v2

    .line 64
    :goto_0
    if-ne p0, v0, :cond_0

    .line 65
    .line 66
    :goto_1
    return-object v0

    .line 67
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    iget v1, p0, Ls10/m;->e:I

    .line 70
    .line 71
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    const/4 v3, 0x1

    .line 74
    if-eqz v1, :cond_6

    .line 75
    .line 76
    if-ne v1, v3, :cond_5

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    :cond_4
    move-object v0, v2

    .line 82
    goto :goto_3

    .line 83
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 84
    .line 85
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 86
    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    iput v3, p0, Ls10/m;->e:I

    .line 95
    .line 96
    iget-object v5, p0, Ls10/m;->f:Ls10/s;

    .line 97
    .line 98
    iget-object p1, v5, Ls10/s;->i:Lkf0/v;

    .line 99
    .line 100
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    check-cast p1, Lyy0/i;

    .line 105
    .line 106
    sget-object v1, Lss0/e;->A:Lss0/e;

    .line 107
    .line 108
    new-instance v3, La50/d;

    .line 109
    .line 110
    const/4 v9, 0x4

    .line 111
    const/16 v10, 0x12

    .line 112
    .line 113
    const/4 v4, 0x2

    .line 114
    const-class v6, Ls10/s;

    .line 115
    .line 116
    const-string v7, "onDemoState"

    .line 117
    .line 118
    const-string v8, "onDemoState(Lcz/skodaauto/myskoda/library/vehicle/model/Capabilities;)V"

    .line 119
    .line 120
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 121
    .line 122
    .line 123
    invoke-static {p1, v1, v3}, Lkp/u6;->e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    new-instance v3, La50/d;

    .line 128
    .line 129
    const/16 v10, 0x13

    .line 130
    .line 131
    const-class v6, Ls10/s;

    .line 132
    .line 133
    const-string v7, "onDemoState"

    .line 134
    .line 135
    const-string v8, "onDemoState(Lcz/skodaauto/myskoda/library/vehicle/model/Capabilities;)V"

    .line 136
    .line 137
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 138
    .line 139
    .line 140
    invoke-static {p1, v1, v3}, Llp/rf;->c(Lzy0/j;Lss0/e;Lay0/n;)Lzy0/j;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    new-instance v1, Ls10/r;

    .line 145
    .line 146
    const/4 v3, 0x0

    .line 147
    const/4 v4, 0x1

    .line 148
    invoke-direct {v1, v4, v3, v5}, Ls10/r;-><init>(ILkotlin/coroutines/Continuation;Ls10/s;)V

    .line 149
    .line 150
    .line 151
    invoke-static {p1, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    new-instance v3, La50/d;

    .line 156
    .line 157
    const/16 v10, 0x14

    .line 158
    .line 159
    const/4 v4, 0x2

    .line 160
    const-class v6, Ls10/s;

    .line 161
    .line 162
    const-string v7, "onDeparturePlanData"

    .line 163
    .line 164
    const-string v8, "onDeparturePlanData(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 165
    .line 166
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 167
    .line 168
    .line 169
    invoke-static {v3, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    if-ne p0, v0, :cond_7

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_7
    move-object p0, v2

    .line 177
    :goto_2
    if-ne p0, v0, :cond_4

    .line 178
    .line 179
    :goto_3
    return-object v0

    .line 180
    nop

    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

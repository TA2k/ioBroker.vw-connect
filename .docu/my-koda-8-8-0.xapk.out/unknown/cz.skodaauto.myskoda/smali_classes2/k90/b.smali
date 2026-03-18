.class public final Lk90/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:I

.field public h:I

.field public i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lk90/b;->d:I

    iput-object p2, p0, Lk90/b;->k:Ljava/lang/Object;

    iput-object p3, p0, Lk90/b;->l:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lte0/a;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lk90/b;->d:I

    .line 2
    iput-object p1, p0, Lk90/b;->i:Ljava/lang/Object;

    iput-object p2, p0, Lk90/b;->l:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Lss/b;Lx41/u0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lk90/b;->d:I

    .line 3
    iput-object p1, p0, Lk90/b;->f:Ljava/lang/Object;

    iput-object p2, p0, Lk90/b;->k:Ljava/lang/Object;

    iput-object p3, p0, Lk90/b;->l:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lr60/f0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lk90/b;->d:I

    .line 4
    iput-object p1, p0, Lk90/b;->l:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lk90/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lk90/b;

    .line 7
    .line 8
    iget-object v1, p0, Lk90/b;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/util/List;

    .line 11
    .line 12
    iget-object v2, p0, Lk90/b;->k:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lss/b;

    .line 15
    .line 16
    iget-object p0, p0, Lk90/b;->l:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lx41/u0;

    .line 19
    .line 20
    invoke-direct {v0, v1, v2, p0, p2}, Lk90/b;-><init>(Ljava/util/List;Lss/b;Lx41/u0;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 24
    .line 25
    return-object v0

    .line 26
    :pswitch_0
    new-instance p1, Lk90/b;

    .line 27
    .line 28
    iget-object v0, p0, Lk90/b;->i:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Ljava/lang/String;

    .line 31
    .line 32
    iget-object p0, p0, Lk90/b;->l:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Lte0/a;

    .line 35
    .line 36
    invoke-direct {p1, v0, p0, p2}, Lk90/b;-><init>(Ljava/lang/String;Lte0/a;Lkotlin/coroutines/Continuation;)V

    .line 37
    .line 38
    .line 39
    return-object p1

    .line 40
    :pswitch_1
    new-instance p1, Lk90/b;

    .line 41
    .line 42
    iget-object p0, p0, Lk90/b;->l:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Lr60/f0;

    .line 45
    .line 46
    invoke-direct {p1, p0, p2}, Lk90/b;-><init>(Lr60/f0;Lkotlin/coroutines/Continuation;)V

    .line 47
    .line 48
    .line 49
    return-object p1

    .line 50
    :pswitch_2
    new-instance p1, Lk90/b;

    .line 51
    .line 52
    iget-object v0, p0, Lk90/b;->k:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Lr60/l;

    .line 55
    .line 56
    iget-object p0, p0, Lk90/b;->l:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Lnn0/e;

    .line 59
    .line 60
    const/4 v1, 0x1

    .line 61
    invoke-direct {p1, v1, v0, p0, p2}, Lk90/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    return-object p1

    .line 65
    :pswitch_3
    new-instance v0, Lk90/b;

    .line 66
    .line 67
    iget-object v1, p0, Lk90/b;->k:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v1, Lk90/c;

    .line 70
    .line 71
    iget-object p0, p0, Lk90/b;->l:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p0, Lk90/a;

    .line 74
    .line 75
    const/4 v2, 0x0

    .line 76
    invoke-direct {v0, v2, v1, p0, p2}, Lk90/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    iput-object p1, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 80
    .line 81
    return-object v0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lk90/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lk90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lk90/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lk90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lk90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lk90/b;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lk90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lk90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lk90/b;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lk90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lk90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lk90/b;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lk90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lyy0/j;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lk90/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lk90/b;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lk90/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lk90/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lk90/b;->l:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lx41/u0;

    .line 11
    .line 12
    iget-object v2, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ljava/util/List;

    .line 15
    .line 16
    iget-object v3, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v3, Lvy0/b0;

    .line 19
    .line 20
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    iget v5, v0, Lk90/b;->h:I

    .line 23
    .line 24
    const/4 v6, 0x2

    .line 25
    const/4 v7, 0x1

    .line 26
    const/4 v8, 0x0

    .line 27
    const/4 v9, 0x0

    .line 28
    if-eqz v5, :cond_2

    .line 29
    .line 30
    if-eq v5, v7, :cond_1

    .line 31
    .line 32
    if-ne v5, v6, :cond_0

    .line 33
    .line 34
    iget-object v1, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v1, Ljava/util/Iterator;

    .line 37
    .line 38
    check-cast v1, Ljava/lang/String;

    .line 39
    .line 40
    iget-object v0, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Lx41/u0;

    .line 43
    .line 44
    check-cast v0, Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 45
    .line 46
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto/16 :goto_3

    .line 50
    .line 51
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_1
    iget v5, v0, Lk90/b;->g:I

    .line 60
    .line 61
    iget-object v10, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v10, Ljava/util/Iterator;

    .line 64
    .line 65
    iget-object v11, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v11, Lx41/u0;

    .line 68
    .line 69
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto/16 :goto_2

    .line 73
    .line 74
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    move-object v5, v2

    .line 78
    check-cast v5, Ljava/lang/Iterable;

    .line 79
    .line 80
    new-instance v10, Ljava/util/ArrayList;

    .line 81
    .line 82
    const/16 v11, 0xa

    .line 83
    .line 84
    invoke-static {v5, v11}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 85
    .line 86
    .line 87
    move-result v11

    .line 88
    invoke-direct {v10, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 89
    .line 90
    .line 91
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v11

    .line 99
    if-eqz v11, :cond_5

    .line 100
    .line 101
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v11

    .line 105
    check-cast v11, Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 106
    .line 107
    const-string v12, "<this>"

    .line 108
    .line 109
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-interface {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getVehicleAntennaIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 113
    .line 114
    .line 115
    move-result-object v12

    .line 116
    invoke-virtual {v12}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    .line 117
    .line 118
    .line 119
    move-result-object v12

    .line 120
    sget-object v13, Lx41/b;->a:[I

    .line 121
    .line 122
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 123
    .line 124
    .line 125
    move-result v12

    .line 126
    aget v12, v13, v12

    .line 127
    .line 128
    if-eq v12, v7, :cond_4

    .line 129
    .line 130
    if-ne v12, v6, :cond_3

    .line 131
    .line 132
    sget-object v12, Lx41/j;->Companion:Lx41/i;

    .line 133
    .line 134
    invoke-interface {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getVin()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v13

    .line 138
    new-instance v14, Lx41/f;

    .line 139
    .line 140
    invoke-static {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformationKt;->getRemoteCredentials(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 141
    .line 142
    .line 143
    move-result-object v15

    .line 144
    invoke-interface {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getMajor-Mh2AYeg()S

    .line 145
    .line 146
    .line 147
    move-result v6

    .line 148
    invoke-interface {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getMinor-Mh2AYeg()S

    .line 149
    .line 150
    .line 151
    move-result v11

    .line 152
    invoke-direct {v14, v15, v6, v11}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 156
    .line 157
    .line 158
    invoke-static {v13, v14}, Lx41/i;->a(Ljava/lang/String;Lx41/f;)Lx41/j;

    .line 159
    .line 160
    .line 161
    move-result-object v6

    .line 162
    goto :goto_1

    .line 163
    :cond_3
    new-instance v0, La8/r0;

    .line 164
    .line 165
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 166
    .line 167
    .line 168
    throw v0

    .line 169
    :cond_4
    sget-object v6, Lx41/j;->Companion:Lx41/i;

    .line 170
    .line 171
    invoke-interface {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getVin()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v12

    .line 175
    new-instance v13, Lx41/f;

    .line 176
    .line 177
    invoke-static {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformationKt;->getRemoteCredentials(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 178
    .line 179
    .line 180
    move-result-object v14

    .line 181
    invoke-interface {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getMajor-Mh2AYeg()S

    .line 182
    .line 183
    .line 184
    move-result v15

    .line 185
    invoke-interface {v11}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getMinor-Mh2AYeg()S

    .line 186
    .line 187
    .line 188
    move-result v11

    .line 189
    invoke-direct {v13, v14, v15, v11}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 193
    .line 194
    .line 195
    const-string v6, "vin"

    .line 196
    .line 197
    invoke-static {v12, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    new-instance v6, Lx41/j;

    .line 201
    .line 202
    invoke-direct {v6, v12, v9, v13}, Lx41/j;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 203
    .line 204
    .line 205
    :goto_1
    invoke-virtual {v10, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    const/4 v6, 0x2

    .line 209
    goto :goto_0

    .line 210
    :cond_5
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 211
    .line 212
    .line 213
    move-result-object v5

    .line 214
    move-object v11, v1

    .line 215
    move-object v10, v5

    .line 216
    move v5, v8

    .line 217
    :cond_6
    :goto_2
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 218
    .line 219
    .line 220
    move-result v6

    .line 221
    if-eqz v6, :cond_7

    .line 222
    .line 223
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v6

    .line 227
    check-cast v6, Lx41/n;

    .line 228
    .line 229
    iput-object v3, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 230
    .line 231
    iput-object v11, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 232
    .line 233
    iput-object v10, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 234
    .line 235
    iput v5, v0, Lk90/b;->g:I

    .line 236
    .line 237
    iput v7, v0, Lk90/b;->h:I

    .line 238
    .line 239
    invoke-virtual {v11, v6, v0}, Lx41/u0;->a(Lx41/n;Lrx0/c;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    if-ne v6, v4, :cond_6

    .line 244
    .line 245
    goto :goto_4

    .line 246
    :cond_7
    iget-object v5, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast v5, Lss/b;

    .line 249
    .line 250
    if-eqz v5, :cond_8

    .line 251
    .line 252
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v2

    .line 256
    check-cast v2, Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 257
    .line 258
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getVin()Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v2

    .line 262
    iget-object v1, v1, Lx41/u0;->i:Lvy0/x;

    .line 263
    .line 264
    new-instance v6, Lwa0/c;

    .line 265
    .line 266
    const/4 v7, 0x6

    .line 267
    invoke-direct {v6, v7, v5, v2, v9}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 268
    .line 269
    .line 270
    iput-object v3, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 271
    .line 272
    iput-object v9, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 273
    .line 274
    iput-object v9, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 275
    .line 276
    iput v8, v0, Lk90/b;->g:I

    .line 277
    .line 278
    const/4 v2, 0x2

    .line 279
    iput v2, v0, Lk90/b;->h:I

    .line 280
    .line 281
    invoke-static {v1, v6, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v0

    .line 285
    if-ne v0, v4, :cond_9

    .line 286
    .line 287
    goto :goto_4

    .line 288
    :cond_8
    new-instance v0, Lx41/y;

    .line 289
    .line 290
    const/16 v1, 0xd

    .line 291
    .line 292
    invoke-direct {v0, v1}, Lx41/y;-><init>(I)V

    .line 293
    .line 294
    .line 295
    const-string v1, "Car2PhonePairing"

    .line 296
    .line 297
    invoke-static {v3, v1, v9, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 298
    .line 299
    .line 300
    :cond_9
    :goto_3
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 301
    .line 302
    :goto_4
    return-object v4

    .line 303
    :pswitch_0
    iget-object v1, v0, Lk90/b;->l:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v1, Lte0/a;

    .line 306
    .line 307
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 308
    .line 309
    iget v3, v0, Lk90/b;->h:I

    .line 310
    .line 311
    const/4 v4, 0x0

    .line 312
    const/4 v5, 0x6

    .line 313
    const/4 v6, 0x1

    .line 314
    if-eqz v3, :cond_b

    .line 315
    .line 316
    if-ne v3, v6, :cond_a

    .line 317
    .line 318
    iget v1, v0, Lk90/b;->g:I

    .line 319
    .line 320
    iget-object v2, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 321
    .line 322
    check-cast v2, Ljavax/crypto/Cipher;

    .line 323
    .line 324
    iget-object v3, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 325
    .line 326
    check-cast v3, [B

    .line 327
    .line 328
    iget-object v6, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast v6, Ljavax/crypto/Cipher;

    .line 331
    .line 332
    iget-object v0, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 333
    .line 334
    check-cast v0, Ljava/util/List;

    .line 335
    .line 336
    check-cast v0, Ljava/util/List;

    .line 337
    .line 338
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 339
    .line 340
    .line 341
    move-object v8, v3

    .line 342
    move-object v3, v0

    .line 343
    move-object/from16 v0, p1

    .line 344
    .line 345
    goto :goto_5

    .line 346
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 347
    .line 348
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 349
    .line 350
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 351
    .line 352
    .line 353
    throw v0

    .line 354
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 355
    .line 356
    .line 357
    iget-object v3, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 358
    .line 359
    check-cast v3, Ljava/lang/String;

    .line 360
    .line 361
    const-string v7, ":"

    .line 362
    .line 363
    filled-new-array {v7}, [Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v7

    .line 367
    invoke-static {v3, v7, v5}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 368
    .line 369
    .line 370
    move-result-object v3

    .line 371
    const-string v7, "AES/GCM/NoPadding"

    .line 372
    .line 373
    invoke-static {v7}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 374
    .line 375
    .line 376
    move-result-object v7

    .line 377
    const-string v8, "getInstance(...)"

    .line 378
    .line 379
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 380
    .line 381
    .line 382
    sget-object v8, Lxx0/c;->e:Lxx0/a;

    .line 383
    .line 384
    invoke-static {v3}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v9

    .line 388
    check-cast v9, Ljava/lang/CharSequence;

    .line 389
    .line 390
    invoke-static {v8, v9, v4, v5}, Lxx0/c;->a(Lxx0/c;Ljava/lang/CharSequence;II)[B

    .line 391
    .line 392
    .line 393
    move-result-object v8

    .line 394
    iget-object v1, v1, Lte0/a;->a:Lte0/c;

    .line 395
    .line 396
    move-object v9, v3

    .line 397
    check-cast v9, Ljava/util/List;

    .line 398
    .line 399
    iput-object v9, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 400
    .line 401
    iput-object v7, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 402
    .line 403
    iput-object v8, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 404
    .line 405
    iput-object v7, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 406
    .line 407
    const/4 v9, 0x2

    .line 408
    iput v9, v0, Lk90/b;->g:I

    .line 409
    .line 410
    iput v6, v0, Lk90/b;->h:I

    .line 411
    .line 412
    check-cast v1, Lre0/c;

    .line 413
    .line 414
    invoke-virtual {v1, v0}, Lre0/c;->a(Lrx0/c;)Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    if-ne v0, v2, :cond_c

    .line 419
    .line 420
    goto :goto_6

    .line 421
    :cond_c
    move-object v2, v7

    .line 422
    move-object v6, v2

    .line 423
    move v1, v9

    .line 424
    :goto_5
    check-cast v0, Ljava/security/Key;

    .line 425
    .line 426
    new-instance v7, Ljavax/crypto/spec/GCMParameterSpec;

    .line 427
    .line 428
    const/16 v9, 0x80

    .line 429
    .line 430
    invoke-direct {v7, v9, v8}, Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V

    .line 431
    .line 432
    .line 433
    invoke-virtual {v2, v1, v0, v7}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 434
    .line 435
    .line 436
    sget-object v0, Lxx0/c;->e:Lxx0/a;

    .line 437
    .line 438
    invoke-static {v3}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 439
    .line 440
    .line 441
    move-result-object v1

    .line 442
    check-cast v1, Ljava/lang/CharSequence;

    .line 443
    .line 444
    invoke-static {v0, v1, v4, v5}, Lxx0/c;->a(Lxx0/c;Ljava/lang/CharSequence;II)[B

    .line 445
    .line 446
    .line 447
    move-result-object v0

    .line 448
    invoke-virtual {v6, v0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    .line 449
    .line 450
    .line 451
    move-result-object v0

    .line 452
    new-instance v2, Ljava/lang/String;

    .line 453
    .line 454
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 455
    .line 456
    .line 457
    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 458
    .line 459
    invoke-direct {v2, v0, v1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 460
    .line 461
    .line 462
    :goto_6
    return-object v2

    .line 463
    :pswitch_1
    iget-object v1, v0, Lk90/b;->l:Ljava/lang/Object;

    .line 464
    .line 465
    check-cast v1, Lr60/f0;

    .line 466
    .line 467
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 468
    .line 469
    iget v3, v0, Lk90/b;->h:I

    .line 470
    .line 471
    const/4 v4, 0x0

    .line 472
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 473
    .line 474
    const/4 v6, 0x3

    .line 475
    const/4 v7, 0x2

    .line 476
    const/4 v8, 0x1

    .line 477
    if-eqz v3, :cond_11

    .line 478
    .line 479
    if-eq v3, v8, :cond_10

    .line 480
    .line 481
    if-eq v3, v7, :cond_f

    .line 482
    .line 483
    if-ne v3, v6, :cond_e

    .line 484
    .line 485
    iget-object v1, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 486
    .line 487
    check-cast v1, Lss0/b;

    .line 488
    .line 489
    check-cast v1, Ler0/g;

    .line 490
    .line 491
    iget-object v0, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 492
    .line 493
    check-cast v0, Lr60/f0;

    .line 494
    .line 495
    check-cast v0, Lss0/b;

    .line 496
    .line 497
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 498
    .line 499
    .line 500
    :cond_d
    :goto_7
    move-object v2, v5

    .line 501
    goto/16 :goto_c

    .line 502
    .line 503
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 504
    .line 505
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 506
    .line 507
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 508
    .line 509
    .line 510
    throw v0

    .line 511
    :cond_f
    iget v1, v0, Lk90/b;->g:I

    .line 512
    .line 513
    iget-object v3, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 514
    .line 515
    check-cast v3, Lr60/f0;

    .line 516
    .line 517
    iget-object v7, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 518
    .line 519
    check-cast v7, Lr60/e0;

    .line 520
    .line 521
    iget-object v9, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v9, Ler0/g;

    .line 524
    .line 525
    iget-object v10, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 526
    .line 527
    check-cast v10, Lss0/b;

    .line 528
    .line 529
    iget-object v11, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 530
    .line 531
    check-cast v11, Lr60/f0;

    .line 532
    .line 533
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 534
    .line 535
    .line 536
    move-object v12, v3

    .line 537
    move v3, v1

    .line 538
    move-object v1, v12

    .line 539
    move-object v12, v7

    .line 540
    move-object/from16 v7, p1

    .line 541
    .line 542
    :goto_8
    move-object/from16 v17, v9

    .line 543
    .line 544
    goto :goto_a

    .line 545
    :cond_10
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 546
    .line 547
    .line 548
    move-object/from16 v3, p1

    .line 549
    .line 550
    goto :goto_9

    .line 551
    :cond_11
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 552
    .line 553
    .line 554
    iget-object v3, v1, Lr60/f0;->k:Lkf0/k;

    .line 555
    .line 556
    iput v8, v0, Lk90/b;->h:I

    .line 557
    .line 558
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 559
    .line 560
    .line 561
    invoke-virtual {v3, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 562
    .line 563
    .line 564
    move-result-object v3

    .line 565
    if-ne v3, v2, :cond_12

    .line 566
    .line 567
    goto/16 :goto_c

    .line 568
    .line 569
    :cond_12
    :goto_9
    move-object v10, v3

    .line 570
    check-cast v10, Lss0/b;

    .line 571
    .line 572
    sget-object v3, Lss0/e;->s1:Lss0/e;

    .line 573
    .line 574
    invoke-static {v10, v3}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 575
    .line 576
    .line 577
    move-result-object v9

    .line 578
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 579
    .line 580
    .line 581
    move-result-object v3

    .line 582
    check-cast v3, Lr60/e0;

    .line 583
    .line 584
    iget-object v11, v1, Lr60/f0;->v:Lhh0/a;

    .line 585
    .line 586
    sget-object v12, Lih0/a;->m:Lih0/a;

    .line 587
    .line 588
    iput-object v1, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 589
    .line 590
    iput-object v10, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 591
    .line 592
    iput-object v9, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 593
    .line 594
    iput-object v3, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 595
    .line 596
    iput-object v1, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 597
    .line 598
    iput v4, v0, Lk90/b;->g:I

    .line 599
    .line 600
    iput v7, v0, Lk90/b;->h:I

    .line 601
    .line 602
    invoke-virtual {v11, v12, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 603
    .line 604
    .line 605
    move-result-object v7

    .line 606
    if-ne v7, v2, :cond_13

    .line 607
    .line 608
    goto/16 :goto_c

    .line 609
    .line 610
    :cond_13
    move-object v11, v1

    .line 611
    move-object v12, v3

    .line 612
    move v3, v4

    .line 613
    goto :goto_8

    .line 614
    :goto_a
    check-cast v7, Ljava/lang/Boolean;

    .line 615
    .line 616
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 617
    .line 618
    .line 619
    move-result v7

    .line 620
    if-eqz v7, :cond_14

    .line 621
    .line 622
    sget-object v7, Lss0/e;->t1:Lss0/e;

    .line 623
    .line 624
    invoke-static {v10, v7}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 625
    .line 626
    .line 627
    move-result v7

    .line 628
    if-eqz v7, :cond_14

    .line 629
    .line 630
    move/from16 v16, v8

    .line 631
    .line 632
    goto :goto_b

    .line 633
    :cond_14
    move/from16 v16, v4

    .line 634
    .line 635
    :goto_b
    iget-object v4, v11, Lr60/f0;->t:Lij0/a;

    .line 636
    .line 637
    const v7, 0x7f120def

    .line 638
    .line 639
    .line 640
    const v8, 0x7f120df0

    .line 641
    .line 642
    .line 643
    invoke-static {v4, v10, v7, v8}, Lkp/m;->d(Lij0/a;Lss0/b;II)Ljava/lang/String;

    .line 644
    .line 645
    .line 646
    move-result-object v13

    .line 647
    iget-object v4, v11, Lr60/f0;->t:Lij0/a;

    .line 648
    .line 649
    const v7, 0x7f120ee0

    .line 650
    .line 651
    .line 652
    const v8, 0x7f120ed3

    .line 653
    .line 654
    .line 655
    invoke-static {v4, v10, v7, v8}, Lkp/m;->d(Lij0/a;Lss0/b;II)Ljava/lang/String;

    .line 656
    .line 657
    .line 658
    move-result-object v18

    .line 659
    const/4 v15, 0x0

    .line 660
    const/16 v19, 0x6

    .line 661
    .line 662
    const/4 v14, 0x0

    .line 663
    invoke-static/range {v12 .. v19}, Lr60/e0;->a(Lr60/e0;Ljava/lang/String;Lql0/g;ZZLer0/g;Ljava/lang/String;I)Lr60/e0;

    .line 664
    .line 665
    .line 666
    move-result-object v4

    .line 667
    move-object/from16 v9, v17

    .line 668
    .line 669
    invoke-virtual {v1, v4}, Lql0/j;->g(Lql0/h;)V

    .line 670
    .line 671
    .line 672
    sget-object v1, Ler0/g;->d:Ler0/g;

    .line 673
    .line 674
    if-ne v9, v1, :cond_15

    .line 675
    .line 676
    iget-object v1, v11, Lr60/f0;->i:Lnn0/e;

    .line 677
    .line 678
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v1

    .line 682
    check-cast v1, Lyy0/i;

    .line 683
    .line 684
    new-instance v4, Lma0/c;

    .line 685
    .line 686
    const/16 v7, 0x18

    .line 687
    .line 688
    invoke-direct {v4, v11, v7}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 689
    .line 690
    .line 691
    const/4 v7, 0x0

    .line 692
    iput-object v7, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 693
    .line 694
    iput-object v7, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 695
    .line 696
    iput-object v7, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 697
    .line 698
    iput-object v7, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 699
    .line 700
    iput-object v7, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 701
    .line 702
    iput v3, v0, Lk90/b;->g:I

    .line 703
    .line 704
    iput v6, v0, Lk90/b;->h:I

    .line 705
    .line 706
    invoke-interface {v1, v4, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 707
    .line 708
    .line 709
    move-result-object v0

    .line 710
    if-ne v0, v2, :cond_d

    .line 711
    .line 712
    goto :goto_c

    .line 713
    :cond_15
    invoke-virtual {v11}, Lql0/j;->a()Lql0/h;

    .line 714
    .line 715
    .line 716
    move-result-object v0

    .line 717
    move-object v12, v0

    .line 718
    check-cast v12, Lr60/e0;

    .line 719
    .line 720
    const/16 v18, 0x0

    .line 721
    .line 722
    const/16 v19, 0x3b

    .line 723
    .line 724
    const/4 v13, 0x0

    .line 725
    const/4 v14, 0x0

    .line 726
    const/4 v15, 0x0

    .line 727
    const/16 v16, 0x0

    .line 728
    .line 729
    const/16 v17, 0x0

    .line 730
    .line 731
    invoke-static/range {v12 .. v19}, Lr60/e0;->a(Lr60/e0;Ljava/lang/String;Lql0/g;ZZLer0/g;Ljava/lang/String;I)Lr60/e0;

    .line 732
    .line 733
    .line 734
    move-result-object v0

    .line 735
    invoke-virtual {v11, v0}, Lql0/j;->g(Lql0/h;)V

    .line 736
    .line 737
    .line 738
    goto/16 :goto_7

    .line 739
    .line 740
    :goto_c
    return-object v2

    .line 741
    :pswitch_2
    iget-object v1, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 742
    .line 743
    check-cast v1, Lr60/l;

    .line 744
    .line 745
    iget-object v2, v1, Lr60/l;->h:Lkf0/k;

    .line 746
    .line 747
    iget-object v3, v1, Lr60/l;->o:Lij0/a;

    .line 748
    .line 749
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 750
    .line 751
    iget v5, v0, Lk90/b;->h:I

    .line 752
    .line 753
    const/4 v7, 0x3

    .line 754
    const/4 v8, 0x2

    .line 755
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 756
    .line 757
    const/4 v10, 0x1

    .line 758
    if-eqz v5, :cond_1a

    .line 759
    .line 760
    if-eq v5, v10, :cond_19

    .line 761
    .line 762
    if-eq v5, v8, :cond_18

    .line 763
    .line 764
    if-ne v5, v7, :cond_17

    .line 765
    .line 766
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 767
    .line 768
    .line 769
    :cond_16
    move-object v4, v9

    .line 770
    goto/16 :goto_12

    .line 771
    .line 772
    :cond_17
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 773
    .line 774
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 775
    .line 776
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 777
    .line 778
    .line 779
    throw v0

    .line 780
    :cond_18
    iget v2, v0, Lk90/b;->g:I

    .line 781
    .line 782
    iget-object v3, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 783
    .line 784
    check-cast v3, Lij0/a;

    .line 785
    .line 786
    iget-object v5, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 787
    .line 788
    check-cast v5, Lr60/l;

    .line 789
    .line 790
    iget-object v8, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 791
    .line 792
    check-cast v8, Ljava/lang/String;

    .line 793
    .line 794
    iget-object v11, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 795
    .line 796
    check-cast v11, Lr60/i;

    .line 797
    .line 798
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 799
    .line 800
    .line 801
    move-object/from16 v18, v8

    .line 802
    .line 803
    move-object/from16 v17, v11

    .line 804
    .line 805
    move-object v11, v5

    .line 806
    move v5, v2

    .line 807
    move-object/from16 v2, p1

    .line 808
    .line 809
    goto/16 :goto_f

    .line 810
    .line 811
    :cond_19
    iget v5, v0, Lk90/b;->g:I

    .line 812
    .line 813
    iget-object v11, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 814
    .line 815
    check-cast v11, Lij0/a;

    .line 816
    .line 817
    iget-object v12, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 818
    .line 819
    check-cast v12, Lr60/l;

    .line 820
    .line 821
    iget-object v13, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 822
    .line 823
    check-cast v13, Lr60/i;

    .line 824
    .line 825
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 826
    .line 827
    .line 828
    move-object v14, v13

    .line 829
    move-object v13, v11

    .line 830
    move-object v11, v12

    .line 831
    move-object/from16 v12, p1

    .line 832
    .line 833
    goto :goto_e

    .line 834
    :cond_1a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 835
    .line 836
    .line 837
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 838
    .line 839
    .line 840
    move-result-object v5

    .line 841
    check-cast v5, Lr60/i;

    .line 842
    .line 843
    iget-object v11, v1, Lr60/l;->l:Lnn0/h;

    .line 844
    .line 845
    invoke-static {v11}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 846
    .line 847
    .line 848
    move-result-object v11

    .line 849
    sget-object v12, Lon0/c;->e:Lon0/c;

    .line 850
    .line 851
    if-ne v11, v12, :cond_1b

    .line 852
    .line 853
    move v11, v10

    .line 854
    goto :goto_d

    .line 855
    :cond_1b
    const/4 v11, 0x0

    .line 856
    :goto_d
    iput-object v5, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 857
    .line 858
    iput-object v1, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 859
    .line 860
    iput-object v3, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 861
    .line 862
    iput v11, v0, Lk90/b;->g:I

    .line 863
    .line 864
    iput v10, v0, Lk90/b;->h:I

    .line 865
    .line 866
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 867
    .line 868
    .line 869
    invoke-virtual {v2, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 870
    .line 871
    .line 872
    move-result-object v12

    .line 873
    if-ne v12, v4, :cond_1c

    .line 874
    .line 875
    goto/16 :goto_12

    .line 876
    .line 877
    :cond_1c
    move-object v13, v3

    .line 878
    move-object v14, v5

    .line 879
    move v5, v11

    .line 880
    move-object v11, v1

    .line 881
    :goto_e
    check-cast v12, Lss0/b;

    .line 882
    .line 883
    const v15, 0x7f120dc7

    .line 884
    .line 885
    .line 886
    const v6, 0x7f120dc6

    .line 887
    .line 888
    .line 889
    invoke-static {v13, v12, v15, v6}, Lkp/m;->d(Lij0/a;Lss0/b;II)Ljava/lang/String;

    .line 890
    .line 891
    .line 892
    move-result-object v6

    .line 893
    iput-object v14, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 894
    .line 895
    iput-object v6, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 896
    .line 897
    iput-object v11, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 898
    .line 899
    iput-object v3, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 900
    .line 901
    iput v5, v0, Lk90/b;->g:I

    .line 902
    .line 903
    iput v8, v0, Lk90/b;->h:I

    .line 904
    .line 905
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 906
    .line 907
    .line 908
    invoke-virtual {v2, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 909
    .line 910
    .line 911
    move-result-object v2

    .line 912
    if-ne v2, v4, :cond_1d

    .line 913
    .line 914
    goto/16 :goto_12

    .line 915
    .line 916
    :cond_1d
    move-object/from16 v18, v6

    .line 917
    .line 918
    move-object/from16 v17, v14

    .line 919
    .line 920
    :goto_f
    check-cast v2, Lss0/b;

    .line 921
    .line 922
    const v6, 0x7f120dc0

    .line 923
    .line 924
    .line 925
    const v8, 0x7f120dc3

    .line 926
    .line 927
    .line 928
    invoke-static {v3, v2, v6, v8}, Lkp/m;->d(Lij0/a;Lss0/b;II)Ljava/lang/String;

    .line 929
    .line 930
    .line 931
    move-result-object v19

    .line 932
    iget-object v2, v1, Lr60/l;->n:Lp60/i;

    .line 933
    .line 934
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 935
    .line 936
    .line 937
    move-result-object v2

    .line 938
    check-cast v2, Ljava/lang/Iterable;

    .line 939
    .line 940
    new-instance v3, Ljava/util/ArrayList;

    .line 941
    .line 942
    const/16 v6, 0xa

    .line 943
    .line 944
    invoke-static {v2, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 945
    .line 946
    .line 947
    move-result v6

    .line 948
    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 949
    .line 950
    .line 951
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 952
    .line 953
    .line 954
    move-result-object v2

    .line 955
    :goto_10
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 956
    .line 957
    .line 958
    move-result v6

    .line 959
    if-eqz v6, :cond_1e

    .line 960
    .line 961
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 962
    .line 963
    .line 964
    move-result-object v6

    .line 965
    check-cast v6, Lq60/b;

    .line 966
    .line 967
    new-instance v8, Lr60/j;

    .line 968
    .line 969
    iget-object v12, v6, Lq60/b;->a:Ljava/lang/String;

    .line 970
    .line 971
    iget-object v6, v6, Lq60/b;->b:Ljava/lang/String;

    .line 972
    .line 973
    invoke-direct {v8, v12, v6}, Lr60/j;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 974
    .line 975
    .line 976
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 977
    .line 978
    .line 979
    goto :goto_10

    .line 980
    :cond_1e
    if-eqz v5, :cond_1f

    .line 981
    .line 982
    move/from16 v32, v10

    .line 983
    .line 984
    goto :goto_11

    .line 985
    :cond_1f
    const/16 v32, 0x0

    .line 986
    .line 987
    :goto_11
    const/16 v33, 0x37fc

    .line 988
    .line 989
    const/16 v20, 0x0

    .line 990
    .line 991
    const/16 v21, 0x0

    .line 992
    .line 993
    const/16 v22, 0x0

    .line 994
    .line 995
    const/16 v23, 0x0

    .line 996
    .line 997
    const/16 v24, 0x0

    .line 998
    .line 999
    const/16 v25, 0x0

    .line 1000
    .line 1001
    const/16 v26, 0x0

    .line 1002
    .line 1003
    const/16 v27, 0x0

    .line 1004
    .line 1005
    const/16 v28, 0x0

    .line 1006
    .line 1007
    const/16 v30, 0x0

    .line 1008
    .line 1009
    const/16 v31, 0x0

    .line 1010
    .line 1011
    move-object/from16 v29, v3

    .line 1012
    .line 1013
    invoke-static/range {v17 .. v33}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v2

    .line 1017
    invoke-virtual {v11, v2}, Lql0/j;->g(Lql0/h;)V

    .line 1018
    .line 1019
    .line 1020
    iget-object v2, v0, Lk90/b;->l:Ljava/lang/Object;

    .line 1021
    .line 1022
    check-cast v2, Lnn0/e;

    .line 1023
    .line 1024
    invoke-virtual {v2}, Lnn0/e;->invoke()Ljava/lang/Object;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v2

    .line 1028
    check-cast v2, Lyy0/i;

    .line 1029
    .line 1030
    new-instance v3, Lr60/h;

    .line 1031
    .line 1032
    const/4 v5, 0x0

    .line 1033
    invoke-direct {v3, v1, v5}, Lr60/h;-><init>(Lr60/l;I)V

    .line 1034
    .line 1035
    .line 1036
    const/4 v1, 0x0

    .line 1037
    iput-object v1, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1038
    .line 1039
    iput-object v1, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 1040
    .line 1041
    iput-object v1, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1042
    .line 1043
    iput-object v1, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1044
    .line 1045
    iput v7, v0, Lk90/b;->h:I

    .line 1046
    .line 1047
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v0

    .line 1051
    if-ne v0, v4, :cond_16

    .line 1052
    .line 1053
    :goto_12
    return-object v4

    .line 1054
    :pswitch_3
    iget-object v1, v0, Lk90/b;->l:Ljava/lang/Object;

    .line 1055
    .line 1056
    check-cast v1, Lk90/a;

    .line 1057
    .line 1058
    iget-object v2, v1, Lk90/a;->a:Lm90/a;

    .line 1059
    .line 1060
    iget-object v3, v0, Lk90/b;->k:Ljava/lang/Object;

    .line 1061
    .line 1062
    check-cast v3, Lk90/c;

    .line 1063
    .line 1064
    iget-object v4, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1065
    .line 1066
    check-cast v4, Lyy0/j;

    .line 1067
    .line 1068
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 1069
    .line 1070
    iget v6, v0, Lk90/b;->h:I

    .line 1071
    .line 1072
    const/4 v7, 0x2

    .line 1073
    const/4 v8, 0x0

    .line 1074
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 1075
    .line 1076
    const/4 v10, 0x0

    .line 1077
    packed-switch v6, :pswitch_data_1

    .line 1078
    .line 1079
    .line 1080
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1081
    .line 1082
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1083
    .line 1084
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1085
    .line 1086
    .line 1087
    throw v0

    .line 1088
    :pswitch_4
    iget-object v0, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1089
    .line 1090
    check-cast v0, Llg0/b;

    .line 1091
    .line 1092
    check-cast v0, Llg0/c;

    .line 1093
    .line 1094
    :goto_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1095
    .line 1096
    .line 1097
    :cond_20
    move-object v5, v9

    .line 1098
    goto/16 :goto_1a

    .line 1099
    .line 1100
    :pswitch_5
    iget v8, v0, Lk90/b;->g:I

    .line 1101
    .line 1102
    iget-object v1, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 1103
    .line 1104
    move-object v4, v1

    .line 1105
    check-cast v4, Lyy0/j;

    .line 1106
    .line 1107
    iget-object v1, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1108
    .line 1109
    check-cast v1, Llg0/b;

    .line 1110
    .line 1111
    check-cast v1, Llg0/c;

    .line 1112
    .line 1113
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1114
    .line 1115
    .line 1116
    move-object/from16 v1, p1

    .line 1117
    .line 1118
    goto/16 :goto_19

    .line 1119
    .line 1120
    :pswitch_6
    iget-object v6, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1121
    .line 1122
    check-cast v6, Llg0/b;

    .line 1123
    .line 1124
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1125
    .line 1126
    .line 1127
    move-object v12, v6

    .line 1128
    move-object/from16 v6, p1

    .line 1129
    .line 1130
    goto/16 :goto_17

    .line 1131
    .line 1132
    :pswitch_7
    iget-object v6, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 1133
    .line 1134
    check-cast v6, Li90/c;

    .line 1135
    .line 1136
    iget-object v11, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1137
    .line 1138
    check-cast v11, Llg0/b;

    .line 1139
    .line 1140
    iget-object v12, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1141
    .line 1142
    check-cast v12, Ljava/lang/String;

    .line 1143
    .line 1144
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1145
    .line 1146
    .line 1147
    move-object/from16 v13, p1

    .line 1148
    .line 1149
    goto/16 :goto_16

    .line 1150
    .line 1151
    :pswitch_8
    iget-object v1, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1152
    .line 1153
    check-cast v1, Llg0/b;

    .line 1154
    .line 1155
    check-cast v1, Lne0/c;

    .line 1156
    .line 1157
    iget-object v0, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1158
    .line 1159
    check-cast v0, Ljava/lang/String;

    .line 1160
    .line 1161
    check-cast v0, Lne0/t;

    .line 1162
    .line 1163
    goto :goto_13

    .line 1164
    :pswitch_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1165
    .line 1166
    .line 1167
    move-object/from16 v6, p1

    .line 1168
    .line 1169
    goto :goto_15

    .line 1170
    :pswitch_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1171
    .line 1172
    .line 1173
    goto :goto_14

    .line 1174
    :pswitch_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1175
    .line 1176
    .line 1177
    iput-object v4, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1178
    .line 1179
    const/4 v6, 0x1

    .line 1180
    iput v6, v0, Lk90/b;->h:I

    .line 1181
    .line 1182
    sget-object v6, Lne0/d;->a:Lne0/d;

    .line 1183
    .line 1184
    invoke-interface {v4, v6, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1185
    .line 1186
    .line 1187
    move-result-object v6

    .line 1188
    if-ne v6, v5, :cond_21

    .line 1189
    .line 1190
    goto/16 :goto_1a

    .line 1191
    .line 1192
    :cond_21
    :goto_14
    iget-object v6, v3, Lk90/c;->b:Lkf0/m;

    .line 1193
    .line 1194
    iput-object v4, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1195
    .line 1196
    iput v7, v0, Lk90/b;->h:I

    .line 1197
    .line 1198
    invoke-virtual {v6, v0}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1199
    .line 1200
    .line 1201
    move-result-object v6

    .line 1202
    if-ne v6, v5, :cond_22

    .line 1203
    .line 1204
    goto/16 :goto_1a

    .line 1205
    .line 1206
    :cond_22
    :goto_15
    check-cast v6, Lne0/t;

    .line 1207
    .line 1208
    instance-of v11, v6, Lne0/c;

    .line 1209
    .line 1210
    if-eqz v11, :cond_23

    .line 1211
    .line 1212
    check-cast v6, Lne0/c;

    .line 1213
    .line 1214
    iput-object v10, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1215
    .line 1216
    iput-object v10, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1217
    .line 1218
    iput-object v10, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1219
    .line 1220
    iput v8, v0, Lk90/b;->g:I

    .line 1221
    .line 1222
    const/4 v1, 0x3

    .line 1223
    iput v1, v0, Lk90/b;->h:I

    .line 1224
    .line 1225
    invoke-interface {v4, v6, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v0

    .line 1229
    if-ne v0, v5, :cond_20

    .line 1230
    .line 1231
    goto/16 :goto_1a

    .line 1232
    .line 1233
    :cond_23
    instance-of v11, v6, Lne0/e;

    .line 1234
    .line 1235
    if-eqz v11, :cond_28

    .line 1236
    .line 1237
    check-cast v6, Lne0/e;

    .line 1238
    .line 1239
    iget-object v6, v6, Lne0/e;->a:Ljava/lang/Object;

    .line 1240
    .line 1241
    check-cast v6, Lss0/k;

    .line 1242
    .line 1243
    iget-object v12, v6, Lss0/k;->a:Ljava/lang/String;

    .line 1244
    .line 1245
    sget-object v6, Llg0/b;->e:Llg0/b;

    .line 1246
    .line 1247
    iget-object v11, v3, Lk90/c;->a:Li90/c;

    .line 1248
    .line 1249
    iget-object v13, v3, Lk90/c;->d:Lam0/c;

    .line 1250
    .line 1251
    iput-object v4, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1252
    .line 1253
    iput-object v12, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1254
    .line 1255
    iput-object v6, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1256
    .line 1257
    iput-object v11, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 1258
    .line 1259
    const/4 v14, 0x4

    .line 1260
    iput v14, v0, Lk90/b;->h:I

    .line 1261
    .line 1262
    invoke-virtual {v13, v0}, Lam0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1263
    .line 1264
    .line 1265
    move-result-object v13

    .line 1266
    if-ne v13, v5, :cond_24

    .line 1267
    .line 1268
    goto/16 :goto_1a

    .line 1269
    .line 1270
    :cond_24
    move-object/from16 v34, v11

    .line 1271
    .line 1272
    move-object v11, v6

    .line 1273
    move-object/from16 v6, v34

    .line 1274
    .line 1275
    :goto_16
    check-cast v13, Lcm0/b;

    .line 1276
    .line 1277
    iput-object v4, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1278
    .line 1279
    iput-object v10, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1280
    .line 1281
    iput-object v11, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1282
    .line 1283
    iput-object v10, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 1284
    .line 1285
    const/4 v14, 0x5

    .line 1286
    iput v14, v0, Lk90/b;->h:I

    .line 1287
    .line 1288
    new-instance v14, Ljava/lang/StringBuilder;

    .line 1289
    .line 1290
    const-string v15, "https://"

    .line 1291
    .line 1292
    invoke-direct {v14, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1293
    .line 1294
    .line 1295
    iget-object v6, v6, Li90/c;->c:Lxl0/g;

    .line 1296
    .line 1297
    invoke-interface {v6, v13}, Lxl0/g;->a(Lcm0/b;)Ljava/lang/String;

    .line 1298
    .line 1299
    .line 1300
    move-result-object v6

    .line 1301
    invoke-virtual {v14, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1302
    .line 1303
    .line 1304
    iget-object v6, v2, Lm90/a;->a:Ljava/lang/String;

    .line 1305
    .line 1306
    filled-new-array {v12, v6}, [Ljava/lang/Object;

    .line 1307
    .line 1308
    .line 1309
    move-result-object v6

    .line 1310
    invoke-static {v6, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1311
    .line 1312
    .line 1313
    move-result-object v6

    .line 1314
    const-string v7, "/api/v1/vehicle-information/%s/certificates/%s"

    .line 1315
    .line 1316
    invoke-static {v7, v6}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 1317
    .line 1318
    .line 1319
    move-result-object v6

    .line 1320
    invoke-virtual {v14, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1321
    .line 1322
    .line 1323
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1324
    .line 1325
    .line 1326
    move-result-object v6

    .line 1327
    const-string v7, "toString(...)"

    .line 1328
    .line 1329
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1330
    .line 1331
    .line 1332
    if-ne v6, v5, :cond_25

    .line 1333
    .line 1334
    goto :goto_1a

    .line 1335
    :cond_25
    move-object v12, v11

    .line 1336
    :goto_17
    move-object v13, v6

    .line 1337
    check-cast v13, Ljava/lang/String;

    .line 1338
    .line 1339
    iget-object v14, v2, Lm90/a;->b:Ljava/lang/String;

    .line 1340
    .line 1341
    iget-object v15, v1, Lk90/a;->b:Ljava/lang/String;

    .line 1342
    .line 1343
    iget-object v1, v1, Lk90/a;->c:Ljava/lang/String;

    .line 1344
    .line 1345
    iget-object v2, v3, Lk90/c;->e:Lkc0/i;

    .line 1346
    .line 1347
    invoke-virtual {v2}, Lkc0/i;->invoke()Ljava/lang/Object;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v2

    .line 1351
    check-cast v2, Ljava/lang/String;

    .line 1352
    .line 1353
    if-eqz v2, :cond_26

    .line 1354
    .line 1355
    const-string v6, "Bearer "

    .line 1356
    .line 1357
    invoke-virtual {v6, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1358
    .line 1359
    .line 1360
    move-result-object v2

    .line 1361
    new-instance v6, Llx0/l;

    .line 1362
    .line 1363
    const-string v7, "Authorization"

    .line 1364
    .line 1365
    invoke-direct {v6, v7, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1366
    .line 1367
    .line 1368
    filled-new-array {v6}, [Llx0/l;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v2

    .line 1372
    invoke-static {v2}, Lmx0/x;->j([Llx0/l;)Ljava/util/HashMap;

    .line 1373
    .line 1374
    .line 1375
    move-result-object v2

    .line 1376
    move-object/from16 v17, v2

    .line 1377
    .line 1378
    goto :goto_18

    .line 1379
    :cond_26
    move-object/from16 v17, v10

    .line 1380
    .line 1381
    :goto_18
    new-instance v11, Llg0/c;

    .line 1382
    .line 1383
    move-object/from16 v16, v1

    .line 1384
    .line 1385
    invoke-direct/range {v11 .. v17}, Llg0/c;-><init>(Llg0/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/HashMap;)V

    .line 1386
    .line 1387
    .line 1388
    iget-object v1, v3, Lk90/c;->c:Lkg0/a;

    .line 1389
    .line 1390
    invoke-virtual {v1, v11}, Lkg0/a;->a(Llg0/c;)Lyy0/m1;

    .line 1391
    .line 1392
    .line 1393
    move-result-object v1

    .line 1394
    iput-object v10, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1395
    .line 1396
    iput-object v10, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1397
    .line 1398
    iput-object v10, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1399
    .line 1400
    iput-object v4, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 1401
    .line 1402
    iput v8, v0, Lk90/b;->g:I

    .line 1403
    .line 1404
    const/4 v2, 0x6

    .line 1405
    iput v2, v0, Lk90/b;->h:I

    .line 1406
    .line 1407
    invoke-static {v1, v0}, Lyy0/u;->z(Lyy0/i;Lrx0/c;)Ljava/lang/Object;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v1

    .line 1411
    if-ne v1, v5, :cond_27

    .line 1412
    .line 1413
    goto :goto_1a

    .line 1414
    :cond_27
    :goto_19
    iput-object v10, v0, Lk90/b;->f:Ljava/lang/Object;

    .line 1415
    .line 1416
    iput-object v10, v0, Lk90/b;->i:Ljava/lang/Object;

    .line 1417
    .line 1418
    iput-object v10, v0, Lk90/b;->j:Ljava/lang/Object;

    .line 1419
    .line 1420
    iput-object v10, v0, Lk90/b;->e:Ljava/lang/Object;

    .line 1421
    .line 1422
    iput v8, v0, Lk90/b;->g:I

    .line 1423
    .line 1424
    const/4 v2, 0x7

    .line 1425
    iput v2, v0, Lk90/b;->h:I

    .line 1426
    .line 1427
    invoke-interface {v4, v1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1428
    .line 1429
    .line 1430
    move-result-object v0

    .line 1431
    if-ne v0, v5, :cond_20

    .line 1432
    .line 1433
    :goto_1a
    return-object v5

    .line 1434
    :cond_28
    new-instance v0, La8/r0;

    .line 1435
    .line 1436
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1437
    .line 1438
    .line 1439
    throw v0

    .line 1440
    nop

    .line 1441
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 1442
    .line 1443
    .line 1444
    .line 1445
    .line 1446
    .line 1447
    .line 1448
    .line 1449
    .line 1450
    .line 1451
    .line 1452
    .line 1453
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
    .end packed-switch
.end method

.class public final Lsk0/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Lsk0/f;

.field public final synthetic f:Lvk0/k0;

.field public final synthetic g:Lxj0/f;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Ljava/lang/Boolean;

.field public final synthetic k:Ljava/lang/String;

.field public final synthetic l:Ljava/util/UUID;

.field public final synthetic m:Ljava/util/List;


# direct methods
.method public constructor <init>(Lsk0/f;Lvk0/k0;Lxj0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lsk0/e;->e:Lsk0/f;

    .line 2
    .line 3
    iput-object p2, p0, Lsk0/e;->f:Lvk0/k0;

    .line 4
    .line 5
    iput-object p3, p0, Lsk0/e;->g:Lxj0/f;

    .line 6
    .line 7
    iput-object p4, p0, Lsk0/e;->h:Ljava/lang/String;

    .line 8
    .line 9
    iput-object p5, p0, Lsk0/e;->i:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p6, p0, Lsk0/e;->j:Ljava/lang/Boolean;

    .line 12
    .line 13
    iput-object p7, p0, Lsk0/e;->k:Ljava/lang/String;

    .line 14
    .line 15
    iput-object p8, p0, Lsk0/e;->l:Ljava/util/UUID;

    .line 16
    .line 17
    iput-object p9, p0, Lsk0/e;->m:Ljava/util/List;

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-direct {p0, p1, p10}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 11

    .line 1
    new-instance v0, Lsk0/e;

    .line 2
    .line 3
    iget-object v8, p0, Lsk0/e;->l:Ljava/util/UUID;

    .line 4
    .line 5
    iget-object v9, p0, Lsk0/e;->m:Ljava/util/List;

    .line 6
    .line 7
    iget-object v1, p0, Lsk0/e;->e:Lsk0/f;

    .line 8
    .line 9
    iget-object v2, p0, Lsk0/e;->f:Lvk0/k0;

    .line 10
    .line 11
    iget-object v3, p0, Lsk0/e;->g:Lxj0/f;

    .line 12
    .line 13
    iget-object v4, p0, Lsk0/e;->h:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v5, p0, Lsk0/e;->i:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v6, p0, Lsk0/e;->j:Ljava/lang/Boolean;

    .line 18
    .line 19
    iget-object v7, p0, Lsk0/e;->k:Ljava/lang/String;

    .line 20
    .line 21
    move-object v10, p1

    .line 22
    invoke-direct/range {v0 .. v10}, Lsk0/e;-><init>(Lsk0/f;Lvk0/k0;Lxj0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lsk0/e;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lsk0/e;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lsk0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 15

    .line 1
    sget-object v14, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v0, p0, Lsk0/e;->d:I

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    const/4 v2, 0x1

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    if-eq v0, v2, :cond_1

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 20
    .line 21
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw v0

    .line 25
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    move-object/from16 v0, p1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Lsk0/e;->e:Lsk0/f;

    .line 35
    .line 36
    iget-object v0, v0, Lsk0/f;->b:Lti0/a;

    .line 37
    .line 38
    iput v2, p0, Lsk0/e;->d:I

    .line 39
    .line 40
    invoke-interface {v0, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    if-ne v0, v14, :cond_3

    .line 45
    .line 46
    goto/16 :goto_5

    .line 47
    .line 48
    :cond_3
    :goto_0
    check-cast v0, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 49
    .line 50
    iget-object v2, p0, Lsk0/e;->f:Lvk0/k0;

    .line 51
    .line 52
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    packed-switch v2, :pswitch_data_0

    .line 57
    .line 58
    .line 59
    new-instance v0, La8/r0;

    .line 60
    .line 61
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :pswitch_0
    const-string v2, "AI_STOPOVER"

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :pswitch_1
    const-string v2, "LOCATION"

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :pswitch_2
    const-string v2, "SERVICE"

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :pswitch_3
    const-string v2, "HOTEL"

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :pswitch_4
    const-string v2, "RESTAURANT"

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :pswitch_5
    const-string v2, "PAY_PARKING_ZONE"

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :pswitch_6
    const-string v2, "PAY_PARKING"

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :pswitch_7
    const-string v2, "PARKING"

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :pswitch_8
    const-string v2, "PAY_GAS_STATION"

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :pswitch_9
    const-string v2, "GAS_STATION"

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :pswitch_a
    const-string v2, "CHARGING_STATION"

    .line 96
    .line 97
    :goto_1
    iget-object v3, p0, Lsk0/e;->g:Lxj0/f;

    .line 98
    .line 99
    const/4 v4, 0x0

    .line 100
    if-eqz v3, :cond_4

    .line 101
    .line 102
    iget-wide v5, v3, Lxj0/f;->a:D

    .line 103
    .line 104
    new-instance v7, Ljava/lang/Double;

    .line 105
    .line 106
    invoke-direct {v7, v5, v6}, Ljava/lang/Double;-><init>(D)V

    .line 107
    .line 108
    .line 109
    move-object v6, v7

    .line 110
    goto :goto_2

    .line 111
    :cond_4
    move-object v6, v4

    .line 112
    :goto_2
    if-eqz v3, :cond_5

    .line 113
    .line 114
    iget-wide v7, v3, Lxj0/f;->b:D

    .line 115
    .line 116
    new-instance v3, Ljava/lang/Double;

    .line 117
    .line 118
    invoke-direct {v3, v7, v8}, Ljava/lang/Double;-><init>(D)V

    .line 119
    .line 120
    .line 121
    move-object v7, v3

    .line 122
    goto :goto_3

    .line 123
    :cond_5
    move-object v7, v4

    .line 124
    :goto_3
    iget-object v3, p0, Lsk0/e;->h:Ljava/lang/String;

    .line 125
    .line 126
    if-nez v3, :cond_6

    .line 127
    .line 128
    move-object v5, v4

    .line 129
    goto :goto_4

    .line 130
    :cond_6
    move-object v5, v3

    .line 131
    :goto_4
    iput v1, p0, Lsk0/e;->d:I

    .line 132
    .line 133
    iget-object v1, p0, Lsk0/e;->i:Ljava/lang/String;

    .line 134
    .line 135
    const/4 v3, 0x0

    .line 136
    iget-object v4, p0, Lsk0/e;->j:Ljava/lang/Boolean;

    .line 137
    .line 138
    iget-object v8, p0, Lsk0/e;->k:Ljava/lang/String;

    .line 139
    .line 140
    iget-object v9, p0, Lsk0/e;->l:Ljava/util/UUID;

    .line 141
    .line 142
    iget-object v10, p0, Lsk0/e;->m:Ljava/util/List;

    .line 143
    .line 144
    const/4 v12, 0x4

    .line 145
    const/4 v13, 0x0

    .line 146
    move-object v11, p0

    .line 147
    invoke-static/range {v0 .. v13}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getPlaceDetail$default(Lcz/myskoda/api/bff_maps/v3/MapsApi;Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    if-ne v0, v14, :cond_7

    .line 152
    .line 153
    :goto_5
    return-object v14

    .line 154
    :cond_7
    return-object v0

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
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

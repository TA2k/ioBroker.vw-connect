.class public final Lu70/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:D

.field public final synthetic g:D

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;DDLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p7, p0, Lu70/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu70/b;->h:Ljava/lang/Object;

    .line 4
    .line 5
    iput-wide p2, p0, Lu70/b;->f:D

    .line 6
    .line 7
    iput-wide p4, p0, Lu70/b;->g:D

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 10

    .line 1
    iget v0, p0, Lu70/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lu70/b;

    .line 7
    .line 8
    iget-object v0, p0, Lu70/b;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v0

    .line 11
    check-cast v2, Ly80/b;

    .line 12
    .line 13
    iget-wide v5, p0, Lu70/b;->g:D

    .line 14
    .line 15
    const/4 v8, 0x1

    .line 16
    iget-wide v3, p0, Lu70/b;->f:D

    .line 17
    .line 18
    move-object v7, p1

    .line 19
    invoke-direct/range {v1 .. v8}, Lu70/b;-><init>(Ljava/lang/Object;DDLkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    return-object v1

    .line 23
    :pswitch_0
    move-object v7, p1

    .line 24
    new-instance v2, Lu70/b;

    .line 25
    .line 26
    iget-object p1, p0, Lu70/b;->h:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v3, p1

    .line 29
    check-cast v3, Lu70/c;

    .line 30
    .line 31
    move-object v8, v7

    .line 32
    iget-wide v6, p0, Lu70/b;->g:D

    .line 33
    .line 34
    const/4 v9, 0x0

    .line 35
    iget-wide v4, p0, Lu70/b;->f:D

    .line 36
    .line 37
    invoke-direct/range {v2 .. v9}, Lu70/b;-><init>(Ljava/lang/Object;DDLkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    return-object v2

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lu70/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lu70/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lu70/b;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lu70/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lu70/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lu70/b;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lu70/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lu70/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lu70/b;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v3, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_2

    .line 22
    :cond_0
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
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, Lu70/b;->h:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p1, Ly80/b;

    .line 40
    .line 41
    iget-object p1, p1, Ly80/b;->b:Lti0/a;

    .line 42
    .line 43
    iput v3, p0, Lu70/b;->e:I

    .line 44
    .line 45
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    if-ne p1, v0, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    :goto_0
    move-object v3, p1

    .line 53
    check-cast v3, Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;

    .line 54
    .line 55
    new-instance v5, Ljava/lang/Double;

    .line 56
    .line 57
    iget-wide v6, p0, Lu70/b;->f:D

    .line 58
    .line 59
    invoke-direct {v5, v6, v7}, Ljava/lang/Double;-><init>(D)V

    .line 60
    .line 61
    .line 62
    new-instance v6, Ljava/lang/Double;

    .line 63
    .line 64
    iget-wide v7, p0, Lu70/b;->g:D

    .line 65
    .line 66
    invoke-direct {v6, v7, v8}, Ljava/lang/Double;-><init>(D)V

    .line 67
    .line 68
    .line 69
    iput v2, p0, Lu70/b;->e:I

    .line 70
    .line 71
    const/4 v4, 0x0

    .line 72
    const/4 v7, 0x0

    .line 73
    const/16 v9, 0x9

    .line 74
    .line 75
    const/4 v10, 0x0

    .line 76
    move-object v8, p0

    .line 77
    invoke-static/range {v3 .. v10}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;->getDealers$default(Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v0, :cond_4

    .line 82
    .line 83
    :goto_1
    move-object p1, v0

    .line 84
    :cond_4
    :goto_2
    return-object p1

    .line 85
    :pswitch_0
    move-object v6, p0

    .line 86
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 87
    .line 88
    iget v0, v6, Lu70/b;->e:I

    .line 89
    .line 90
    const/4 v1, 0x2

    .line 91
    const/4 v2, 0x1

    .line 92
    if-eqz v0, :cond_7

    .line 93
    .line 94
    if-eq v0, v2, :cond_6

    .line 95
    .line 96
    if-ne v0, v1, :cond_5

    .line 97
    .line 98
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 103
    .line 104
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 105
    .line 106
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw p0

    .line 110
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    iget-object p1, v6, Lu70/b;->h:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast p1, Lu70/c;

    .line 120
    .line 121
    iget-object p1, p1, Lu70/c;->b:Lti0/a;

    .line 122
    .line 123
    iput v2, v6, Lu70/b;->e:I

    .line 124
    .line 125
    invoke-interface {p1, v6}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    if-ne p1, p0, :cond_8

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_8
    :goto_3
    move-object v0, p1

    .line 133
    check-cast v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 134
    .line 135
    new-instance v2, Ljava/lang/Double;

    .line 136
    .line 137
    iget-wide v3, v6, Lu70/b;->f:D

    .line 138
    .line 139
    invoke-direct {v2, v3, v4}, Ljava/lang/Double;-><init>(D)V

    .line 140
    .line 141
    .line 142
    new-instance v3, Ljava/lang/Double;

    .line 143
    .line 144
    iget-wide v4, v6, Lu70/b;->g:D

    .line 145
    .line 146
    invoke-direct {v3, v4, v5}, Ljava/lang/Double;-><init>(D)V

    .line 147
    .line 148
    .line 149
    iput v1, v6, Lu70/b;->e:I

    .line 150
    .line 151
    const/4 v1, 0x0

    .line 152
    const/4 v4, 0x0

    .line 153
    const/4 v5, 0x0

    .line 154
    const/16 v7, 0x19

    .line 155
    .line 156
    const/4 v8, 0x0

    .line 157
    invoke-static/range {v0 .. v8}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->getServicePartners$default(Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Float;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    if-ne p1, p0, :cond_9

    .line 162
    .line 163
    :goto_4
    move-object p1, p0

    .line 164
    :cond_9
    :goto_5
    return-object p1

    .line 165
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

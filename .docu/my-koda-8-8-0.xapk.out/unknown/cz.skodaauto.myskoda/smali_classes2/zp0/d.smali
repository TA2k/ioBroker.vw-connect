.class public final Lzp0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lzp0/e;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lzp0/e;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lzp0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzp0/d;->f:Lzp0/e;

    .line 4
    .line 5
    iput-object p2, p0, Lzp0/d;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lzp0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lzp0/d;

    .line 7
    .line 8
    iget-object v1, p0, Lzp0/d;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    iget-object p0, p0, Lzp0/d;->f:Lzp0/e;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p1, v2}, Lzp0/d;-><init>(Lzp0/e;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lzp0/d;

    .line 18
    .line 19
    iget-object v1, p0, Lzp0/d;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    iget-object p0, p0, Lzp0/d;->f:Lzp0/e;

    .line 23
    .line 24
    invoke-direct {v0, p0, v1, p1, v2}, Lzp0/d;-><init>(Lzp0/e;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lzp0/d;

    .line 29
    .line 30
    iget-object v1, p0, Lzp0/d;->g:Ljava/lang/String;

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    iget-object p0, p0, Lzp0/d;->f:Lzp0/e;

    .line 34
    .line 35
    invoke-direct {v0, p0, v1, p1, v2}, Lzp0/d;-><init>(Lzp0/e;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lzp0/d;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lzp0/d;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lzp0/d;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lzp0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lzp0/d;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lzp0/d;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lzp0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Lzp0/d;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lzp0/d;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lzp0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lzp0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lzp0/d;->e:I

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
    iget-object p1, p0, Lzp0/d;->f:Lzp0/e;

    .line 38
    .line 39
    iget-object p1, p1, Lzp0/e;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Lzp0/d;->e:I

    .line 42
    .line 43
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-ne p1, v0, :cond_3

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    :goto_0
    check-cast p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 51
    .line 52
    iput v2, p0, Lzp0/d;->e:I

    .line 53
    .line 54
    iget-object v1, p0, Lzp0/d;->g:Ljava/lang/String;

    .line 55
    .line 56
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->deleteServicePartnerFromVehicle(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    if-ne p1, v0, :cond_4

    .line 61
    .line 62
    :goto_1
    move-object p1, v0

    .line 63
    :cond_4
    :goto_2
    return-object p1

    .line 64
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    iget v1, p0, Lzp0/d;->e:I

    .line 67
    .line 68
    const/4 v2, 0x2

    .line 69
    const/4 v3, 0x1

    .line 70
    if-eqz v1, :cond_7

    .line 71
    .line 72
    if-eq v1, v3, :cond_6

    .line 73
    .line 74
    if-ne v1, v2, :cond_5

    .line 75
    .line 76
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_5

    .line 80
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 81
    .line 82
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    iget-object p1, p0, Lzp0/d;->f:Lzp0/e;

    .line 96
    .line 97
    iget-object p1, p1, Lzp0/e;->b:Lti0/a;

    .line 98
    .line 99
    iput v3, p0, Lzp0/d;->e:I

    .line 100
    .line 101
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    if-ne p1, v0, :cond_8

    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 109
    .line 110
    iput v2, p0, Lzp0/d;->e:I

    .line 111
    .line 112
    iget-object v1, p0, Lzp0/d;->g:Ljava/lang/String;

    .line 113
    .line 114
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->getVehicleServiceInformation(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    if-ne p1, v0, :cond_9

    .line 119
    .line 120
    :goto_4
    move-object p1, v0

    .line 121
    :cond_9
    :goto_5
    return-object p1

    .line 122
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 123
    .line 124
    iget v1, p0, Lzp0/d;->e:I

    .line 125
    .line 126
    const/4 v2, 0x2

    .line 127
    const/4 v3, 0x1

    .line 128
    if-eqz v1, :cond_c

    .line 129
    .line 130
    if-eq v1, v3, :cond_b

    .line 131
    .line 132
    if-ne v1, v2, :cond_a

    .line 133
    .line 134
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    goto :goto_8

    .line 138
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 139
    .line 140
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 141
    .line 142
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    throw p0

    .line 146
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    goto :goto_6

    .line 150
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    iget-object p1, p0, Lzp0/d;->f:Lzp0/e;

    .line 154
    .line 155
    iget-object p1, p1, Lzp0/e;->b:Lti0/a;

    .line 156
    .line 157
    iput v3, p0, Lzp0/d;->e:I

    .line 158
    .line 159
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    if-ne p1, v0, :cond_d

    .line 164
    .line 165
    goto :goto_7

    .line 166
    :cond_d
    :goto_6
    check-cast p1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 167
    .line 168
    iput v2, p0, Lzp0/d;->e:I

    .line 169
    .line 170
    iget-object v1, p0, Lzp0/d;->g:Ljava/lang/String;

    .line 171
    .line 172
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->getVehicleServiceInformation(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    if-ne p1, v0, :cond_e

    .line 177
    .line 178
    :goto_7
    move-object p1, v0

    .line 179
    :cond_e
    :goto_8
    return-object p1

    .line 180
    nop

    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.class public final Ljb0/w;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljb0/x;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Z


# direct methods
.method public synthetic constructor <init>(Ljb0/x;Ljava/lang/String;ZLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Ljb0/w;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljb0/w;->f:Ljb0/x;

    .line 4
    .line 5
    iput-object p2, p0, Ljb0/w;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-boolean p3, p0, Ljb0/w;->h:Z

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Ljb0/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljb0/w;

    .line 7
    .line 8
    iget-boolean v4, p0, Ljb0/w;->h:Z

    .line 9
    .line 10
    const/4 v6, 0x2

    .line 11
    iget-object v2, p0, Ljb0/w;->f:Ljb0/x;

    .line 12
    .line 13
    iget-object v3, p0, Ljb0/w;->g:Ljava/lang/String;

    .line 14
    .line 15
    move-object v5, p1

    .line 16
    invoke-direct/range {v1 .. v6}, Ljb0/w;-><init>(Ljb0/x;Ljava/lang/String;ZLkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    return-object v1

    .line 20
    :pswitch_0
    move-object v6, p1

    .line 21
    new-instance v2, Ljb0/w;

    .line 22
    .line 23
    iget-boolean v5, p0, Ljb0/w;->h:Z

    .line 24
    .line 25
    const/4 v7, 0x1

    .line 26
    iget-object v3, p0, Ljb0/w;->f:Ljb0/x;

    .line 27
    .line 28
    iget-object v4, p0, Ljb0/w;->g:Ljava/lang/String;

    .line 29
    .line 30
    invoke-direct/range {v2 .. v7}, Ljb0/w;-><init>(Ljb0/x;Ljava/lang/String;ZLkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    return-object v2

    .line 34
    :pswitch_1
    move-object v6, p1

    .line 35
    new-instance v2, Ljb0/w;

    .line 36
    .line 37
    iget-boolean v5, p0, Ljb0/w;->h:Z

    .line 38
    .line 39
    const/4 v7, 0x0

    .line 40
    iget-object v3, p0, Ljb0/w;->f:Ljb0/x;

    .line 41
    .line 42
    iget-object v4, p0, Ljb0/w;->g:Ljava/lang/String;

    .line 43
    .line 44
    invoke-direct/range {v2 .. v7}, Ljb0/w;-><init>(Ljb0/x;Ljava/lang/String;ZLkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    return-object v2

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ljb0/w;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljb0/w;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljb0/w;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljb0/w;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ljb0/w;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljb0/w;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljb0/w;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Ljb0/w;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljb0/w;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Ljb0/w;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ljb0/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ljb0/w;->e:I

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
    iget-object p1, p0, Ljb0/w;->f:Ljb0/x;

    .line 38
    .line 39
    iget-object p1, p1, Ljb0/x;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Ljb0/w;->e:I

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
    check-cast p1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 51
    .line 52
    new-instance v1, Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;

    .line 53
    .line 54
    iget-boolean v3, p0, Ljb0/w;->h:Z

    .line 55
    .line 56
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;-><init>(Z)V

    .line 57
    .line 58
    .line 59
    iput v2, p0, Ljb0/w;->e:I

    .line 60
    .line 61
    iget-object v2, p0, Ljb0/w;->g:Ljava/lang/String;

    .line 62
    .line 63
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setAirConditioningWindowsHeating(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    if-ne p1, v0, :cond_4

    .line 68
    .line 69
    :goto_1
    move-object p1, v0

    .line 70
    :cond_4
    :goto_2
    return-object p1

    .line 71
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    iget v1, p0, Ljb0/w;->e:I

    .line 74
    .line 75
    const/4 v2, 0x2

    .line 76
    const/4 v3, 0x1

    .line 77
    if-eqz v1, :cond_7

    .line 78
    .line 79
    if-eq v1, v3, :cond_6

    .line 80
    .line 81
    if-ne v1, v2, :cond_5

    .line 82
    .line 83
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    goto :goto_5

    .line 87
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 88
    .line 89
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 90
    .line 91
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw p0

    .line 95
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    iget-object p1, p0, Ljb0/w;->f:Ljb0/x;

    .line 103
    .line 104
    iget-object p1, p1, Ljb0/x;->b:Lti0/a;

    .line 105
    .line 106
    iput v3, p0, Ljb0/w;->e:I

    .line 107
    .line 108
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-ne p1, v0, :cond_8

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 116
    .line 117
    new-instance v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;

    .line 118
    .line 119
    iget-boolean v3, p0, Ljb0/w;->h:Z

    .line 120
    .line 121
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;-><init>(Z)V

    .line 122
    .line 123
    .line 124
    iput v2, p0, Ljb0/w;->e:I

    .line 125
    .line 126
    iget-object v2, p0, Ljb0/w;->g:Ljava/lang/String;

    .line 127
    .line 128
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setAirConditioningWithoutExternalPower(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-ne p1, v0, :cond_9

    .line 133
    .line 134
    :goto_4
    move-object p1, v0

    .line 135
    :cond_9
    :goto_5
    return-object p1

    .line 136
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 137
    .line 138
    iget v1, p0, Ljb0/w;->e:I

    .line 139
    .line 140
    const/4 v2, 0x2

    .line 141
    const/4 v3, 0x1

    .line 142
    if-eqz v1, :cond_c

    .line 143
    .line 144
    if-eq v1, v3, :cond_b

    .line 145
    .line 146
    if-ne v1, v2, :cond_a

    .line 147
    .line 148
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    goto :goto_8

    .line 152
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 153
    .line 154
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 155
    .line 156
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    throw p0

    .line 160
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    goto :goto_6

    .line 164
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    iget-object p1, p0, Ljb0/w;->f:Ljb0/x;

    .line 168
    .line 169
    iget-object p1, p1, Ljb0/x;->b:Lti0/a;

    .line 170
    .line 171
    iput v3, p0, Ljb0/w;->e:I

    .line 172
    .line 173
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p1

    .line 177
    if-ne p1, v0, :cond_d

    .line 178
    .line 179
    goto :goto_7

    .line 180
    :cond_d
    :goto_6
    check-cast p1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 181
    .line 182
    new-instance v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;

    .line 183
    .line 184
    iget-boolean v3, p0, Ljb0/w;->h:Z

    .line 185
    .line 186
    invoke-direct {v1, v3}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;-><init>(Z)V

    .line 187
    .line 188
    .line 189
    iput v2, p0, Ljb0/w;->e:I

    .line 190
    .line 191
    iget-object v2, p0, Ljb0/w;->g:Ljava/lang/String;

    .line 192
    .line 193
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setAirConditioningAtUnlock(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object p1

    .line 197
    if-ne p1, v0, :cond_e

    .line 198
    .line 199
    :goto_7
    move-object p1, v0

    .line 200
    :cond_e
    :goto_8
    return-object p1

    .line 201
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

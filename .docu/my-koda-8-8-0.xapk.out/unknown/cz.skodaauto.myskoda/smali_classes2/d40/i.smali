.class public final Ld40/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ld40/n;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ld40/n;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Ld40/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld40/i;->f:Ld40/n;

    .line 4
    .line 5
    iput-object p2, p0, Ld40/i;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Ld40/i;->h:Ljava/lang/String;

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
    iget v0, p0, Ld40/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Ld40/i;

    .line 7
    .line 8
    iget-object v4, p0, Ld40/i;->h:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v6, 0x2

    .line 11
    iget-object v2, p0, Ld40/i;->f:Ld40/n;

    .line 12
    .line 13
    iget-object v3, p0, Ld40/i;->g:Ljava/lang/String;

    .line 14
    .line 15
    move-object v5, p1

    .line 16
    invoke-direct/range {v1 .. v6}, Ld40/i;-><init>(Ld40/n;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    return-object v1

    .line 20
    :pswitch_0
    move-object v6, p1

    .line 21
    new-instance v2, Ld40/i;

    .line 22
    .line 23
    iget-object v5, p0, Ld40/i;->h:Ljava/lang/String;

    .line 24
    .line 25
    const/4 v7, 0x1

    .line 26
    iget-object v3, p0, Ld40/i;->f:Ld40/n;

    .line 27
    .line 28
    iget-object v4, p0, Ld40/i;->g:Ljava/lang/String;

    .line 29
    .line 30
    invoke-direct/range {v2 .. v7}, Ld40/i;-><init>(Ld40/n;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    return-object v2

    .line 34
    :pswitch_1
    move-object v6, p1

    .line 35
    new-instance v2, Ld40/i;

    .line 36
    .line 37
    iget-object v5, p0, Ld40/i;->h:Ljava/lang/String;

    .line 38
    .line 39
    const/4 v7, 0x0

    .line 40
    iget-object v3, p0, Ld40/i;->f:Ld40/n;

    .line 41
    .line 42
    iget-object v4, p0, Ld40/i;->g:Ljava/lang/String;

    .line 43
    .line 44
    invoke-direct/range {v2 .. v7}, Ld40/i;-><init>(Ld40/n;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ld40/i;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ld40/i;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ld40/i;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ld40/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ld40/i;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ld40/i;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ld40/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Ld40/i;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ld40/i;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Ld40/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ld40/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ld40/i;->e:I

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
    iget-object p1, p0, Ld40/i;->f:Ld40/n;

    .line 38
    .line 39
    iget-object p1, p1, Ld40/n;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Ld40/i;->e:I

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
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 51
    .line 52
    iput v2, p0, Ld40/i;->e:I

    .line 53
    .line 54
    iget-object v1, p0, Ld40/i;->g:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v2, p0, Ld40/i;->h:Ljava/lang/String;

    .line 57
    .line 58
    invoke-interface {p1, v1, v2, p0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->unsubscribeUserFromLoyaltyChallenge(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    if-ne p1, v0, :cond_4

    .line 63
    .line 64
    :goto_1
    move-object p1, v0

    .line 65
    :cond_4
    :goto_2
    return-object p1

    .line 66
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 67
    .line 68
    iget v1, p0, Ld40/i;->e:I

    .line 69
    .line 70
    const/4 v2, 0x2

    .line 71
    const/4 v3, 0x1

    .line 72
    if-eqz v1, :cond_7

    .line 73
    .line 74
    if-eq v1, v3, :cond_6

    .line 75
    .line 76
    if-ne v1, v2, :cond_5

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_5

    .line 82
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 85
    .line 86
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    iget-object p1, p0, Ld40/i;->f:Ld40/n;

    .line 98
    .line 99
    iget-object p1, p1, Ld40/n;->b:Lti0/a;

    .line 100
    .line 101
    iput v3, p0, Ld40/i;->e:I

    .line 102
    .line 103
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    if-ne p1, v0, :cond_8

    .line 108
    .line 109
    goto :goto_4

    .line 110
    :cond_8
    :goto_3
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 111
    .line 112
    iget-object v1, p0, Ld40/i;->h:Ljava/lang/String;

    .line 113
    .line 114
    if-nez v1, :cond_9

    .line 115
    .line 116
    const/4 v1, 0x0

    .line 117
    :cond_9
    iput v2, p0, Ld40/i;->e:I

    .line 118
    .line 119
    iget-object v2, p0, Ld40/i;->g:Ljava/lang/String;

    .line 120
    .line 121
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->getLoyaltyMemberChallenges(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    if-ne p1, v0, :cond_a

    .line 126
    .line 127
    :goto_4
    move-object p1, v0

    .line 128
    :cond_a
    :goto_5
    return-object p1

    .line 129
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 130
    .line 131
    iget v1, p0, Ld40/i;->e:I

    .line 132
    .line 133
    const/4 v2, 0x2

    .line 134
    const/4 v3, 0x1

    .line 135
    if-eqz v1, :cond_d

    .line 136
    .line 137
    if-eq v1, v3, :cond_c

    .line 138
    .line 139
    if-ne v1, v2, :cond_b

    .line 140
    .line 141
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    goto :goto_8

    .line 145
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 148
    .line 149
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    throw p0

    .line 153
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iget-object p1, p0, Ld40/i;->f:Ld40/n;

    .line 161
    .line 162
    iget-object p1, p1, Ld40/n;->b:Lti0/a;

    .line 163
    .line 164
    iput v3, p0, Ld40/i;->e:I

    .line 165
    .line 166
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    if-ne p1, v0, :cond_e

    .line 171
    .line 172
    goto :goto_7

    .line 173
    :cond_e
    :goto_6
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 174
    .line 175
    iput v2, p0, Ld40/i;->e:I

    .line 176
    .line 177
    iget-object v1, p0, Ld40/i;->g:Ljava/lang/String;

    .line 178
    .line 179
    iget-object v2, p0, Ld40/i;->h:Ljava/lang/String;

    .line 180
    .line 181
    invoke-interface {p1, v1, v2, p0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->collectBadge(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    if-ne p1, v0, :cond_f

    .line 186
    .line 187
    :goto_7
    move-object p1, v0

    .line 188
    :cond_f
    :goto_8
    return-object p1

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.class public final Li70/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Li70/t;Ll70/k;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Li70/s;->d:I

    .line 1
    iput-object p1, p0, Li70/s;->i:Ljava/lang/Object;

    iput-object p2, p0, Li70/s;->j:Ljava/lang/Object;

    iput-object p3, p0, Li70/s;->f:Ljava/lang/String;

    iput-object p4, p0, Li70/s;->g:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lnp0/c;Lqp0/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Li70/s;->d:I

    .line 2
    iput-object p1, p0, Li70/s;->h:Ljava/lang/Object;

    iput-object p2, p0, Li70/s;->i:Ljava/lang/Object;

    iput-object p3, p0, Li70/s;->f:Ljava/lang/String;

    iput-object p4, p0, Li70/s;->g:Ljava/lang/Object;

    iput-object p5, p0, Li70/s;->j:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lyk0/q;Lxj0/f;Lxj0/f;Ljava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Li70/s;->d:I

    .line 3
    iput-object p1, p0, Li70/s;->h:Ljava/lang/Object;

    iput-object p2, p0, Li70/s;->i:Ljava/lang/Object;

    iput-object p3, p0, Li70/s;->j:Ljava/lang/Object;

    iput-object p4, p0, Li70/s;->g:Ljava/lang/Object;

    iput-object p5, p0, Li70/s;->f:Ljava/lang/String;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    iget v0, p0, Li70/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Li70/s;

    .line 7
    .line 8
    iget-object v0, p0, Li70/s;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v0

    .line 11
    check-cast v2, Lyk0/q;

    .line 12
    .line 13
    iget-object v0, p0, Li70/s;->i:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v0

    .line 16
    check-cast v3, Lxj0/f;

    .line 17
    .line 18
    iget-object v0, p0, Li70/s;->j:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    check-cast v4, Lxj0/f;

    .line 22
    .line 23
    iget-object v0, p0, Li70/s;->g:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v5, v0

    .line 26
    check-cast v5, Ljava/util/UUID;

    .line 27
    .line 28
    iget-object v6, p0, Li70/s;->f:Ljava/lang/String;

    .line 29
    .line 30
    move-object v7, p1

    .line 31
    invoke-direct/range {v1 .. v7}, Li70/s;-><init>(Lyk0/q;Lxj0/f;Lxj0/f;Ljava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 32
    .line 33
    .line 34
    return-object v1

    .line 35
    :pswitch_0
    move-object v7, p1

    .line 36
    new-instance v2, Li70/s;

    .line 37
    .line 38
    iget-object p1, p0, Li70/s;->h:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v3, p1

    .line 41
    check-cast v3, Lnp0/c;

    .line 42
    .line 43
    iget-object p1, p0, Li70/s;->i:Ljava/lang/Object;

    .line 44
    .line 45
    move-object v4, p1

    .line 46
    check-cast v4, Lqp0/q;

    .line 47
    .line 48
    iget-object p1, p0, Li70/s;->g:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v6, p1

    .line 51
    check-cast v6, Ljava/lang/String;

    .line 52
    .line 53
    iget-object p1, p0, Li70/s;->j:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p1, Ljava/lang/String;

    .line 56
    .line 57
    iget-object v5, p0, Li70/s;->f:Ljava/lang/String;

    .line 58
    .line 59
    move-object v8, v7

    .line 60
    move-object v7, p1

    .line 61
    invoke-direct/range {v2 .. v8}, Li70/s;-><init>(Lnp0/c;Lqp0/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    return-object v2

    .line 65
    :pswitch_1
    move-object v7, p1

    .line 66
    new-instance v2, Li70/s;

    .line 67
    .line 68
    iget-object p1, p0, Li70/s;->i:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v3, p1

    .line 71
    check-cast v3, Li70/t;

    .line 72
    .line 73
    iget-object p1, p0, Li70/s;->j:Ljava/lang/Object;

    .line 74
    .line 75
    move-object v4, p1

    .line 76
    check-cast v4, Ll70/k;

    .line 77
    .line 78
    iget-object p1, p0, Li70/s;->g:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v6, p1

    .line 81
    check-cast v6, Ljava/lang/String;

    .line 82
    .line 83
    iget-object v5, p0, Li70/s;->f:Ljava/lang/String;

    .line 84
    .line 85
    invoke-direct/range {v2 .. v7}, Li70/s;-><init>(Li70/t;Ll70/k;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 86
    .line 87
    .line 88
    return-object v2

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li70/s;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Li70/s;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Li70/s;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Li70/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Li70/s;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Li70/s;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Li70/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Li70/s;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Li70/s;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Li70/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 20

    .line 1
    move-object/from16 v6, p0

    .line 2
    .line 3
    iget v0, v6, Li70/s;->d:I

    .line 4
    .line 5
    iget-object v1, v6, Li70/s;->f:Ljava/lang/String;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    iget-object v3, v6, Li70/s;->g:Ljava/lang/Object;

    .line 9
    .line 10
    iget-object v4, v6, Li70/s;->j:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object v5, v6, Li70/s;->i:Ljava/lang/Object;

    .line 13
    .line 14
    const-string v7, "call to \'resume\' before \'invoke\' with coroutine"

    .line 15
    .line 16
    const/4 v8, 0x1

    .line 17
    const/4 v9, 0x2

    .line 18
    packed-switch v0, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    sget-object v12, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    iget v0, v6, Li70/s;->e:I

    .line 24
    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    if-eq v0, v8, :cond_1

    .line 28
    .line 29
    if-ne v0, v9, :cond_0

    .line 30
    .line 31
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    move-object/from16 v0, p1

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v0

    .line 43
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    move-object/from16 v0, p1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object v0, v6, Li70/s;->h:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Lyk0/q;

    .line 55
    .line 56
    iget-object v0, v0, Lyk0/q;->b:Lti0/a;

    .line 57
    .line 58
    iput v8, v6, Li70/s;->e:I

    .line 59
    .line 60
    invoke-interface {v0, v6}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    if-ne v0, v12, :cond_3

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    :goto_0
    check-cast v0, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 68
    .line 69
    check-cast v5, Lxj0/f;

    .line 70
    .line 71
    move-object v10, v1

    .line 72
    move-object v11, v2

    .line 73
    iget-wide v1, v5, Lxj0/f;->a:D

    .line 74
    .line 75
    iget-wide v7, v5, Lxj0/f;->b:D

    .line 76
    .line 77
    check-cast v4, Lxj0/f;

    .line 78
    .line 79
    iget-wide v13, v4, Lxj0/f;->a:D

    .line 80
    .line 81
    iget-wide v4, v4, Lxj0/f;->b:D

    .line 82
    .line 83
    check-cast v3, Ljava/util/UUID;

    .line 84
    .line 85
    if-nez v10, :cond_4

    .line 86
    .line 87
    move-object v10, v11

    .line 88
    :cond_4
    iput v9, v6, Li70/s;->e:I

    .line 89
    .line 90
    move-object v9, v3

    .line 91
    move-object v11, v6

    .line 92
    move-wide/from16 v18, v7

    .line 93
    .line 94
    move-wide v7, v4

    .line 95
    move-wide/from16 v3, v18

    .line 96
    .line 97
    move-wide v5, v13

    .line 98
    invoke-interface/range {v0 .. v11}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getOffers(DDDDLjava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    if-ne v0, v12, :cond_5

    .line 103
    .line 104
    :goto_1
    move-object v0, v12

    .line 105
    :cond_5
    :goto_2
    return-object v0

    .line 106
    :pswitch_0
    move-object v10, v1

    .line 107
    move-object v11, v2

    .line 108
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 109
    .line 110
    iget v1, v6, Li70/s;->e:I

    .line 111
    .line 112
    if-eqz v1, :cond_8

    .line 113
    .line 114
    if-eq v1, v8, :cond_7

    .line 115
    .line 116
    if-ne v1, v9, :cond_6

    .line 117
    .line 118
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object/from16 v0, p1

    .line 122
    .line 123
    goto/16 :goto_6

    .line 124
    .line 125
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw v0

    .line 131
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    move-object/from16 v1, p1

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    iget-object v1, v6, Li70/s;->h:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v1, Lnp0/c;

    .line 143
    .line 144
    iget-object v1, v1, Lnp0/c;->c:Lti0/a;

    .line 145
    .line 146
    iput v8, v6, Li70/s;->e:I

    .line 147
    .line 148
    invoke-interface {v1, v6}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    if-ne v1, v0, :cond_9

    .line 153
    .line 154
    goto :goto_6

    .line 155
    :cond_9
    :goto_3
    check-cast v1, Lcz/myskoda/api/bff_ai_assistant/v2/AiAssistantApi;

    .line 156
    .line 157
    check-cast v5, Lqp0/q;

    .line 158
    .line 159
    sget-object v2, Lnp0/h;->a:Ljava/util/List;

    .line 160
    .line 161
    iget-object v2, v5, Lqp0/q;->a:Lxj0/f;

    .line 162
    .line 163
    if-eqz v2, :cond_a

    .line 164
    .line 165
    new-instance v7, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 166
    .line 167
    iget-wide v12, v2, Lxj0/f;->a:D

    .line 168
    .line 169
    iget-wide v14, v2, Lxj0/f;->b:D

    .line 170
    .line 171
    invoke-direct {v7, v12, v13, v14, v15}, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;-><init>(DD)V

    .line 172
    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_a
    move-object v7, v11

    .line 176
    :goto_4
    iget-object v2, v5, Lqp0/q;->b:Lqp0/r;

    .line 177
    .line 178
    if-eqz v2, :cond_b

    .line 179
    .line 180
    new-instance v12, Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerPreferencesDto;

    .line 181
    .line 182
    iget-boolean v5, v2, Lqp0/r;->g:Z

    .line 183
    .line 184
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 185
    .line 186
    .line 187
    move-result-object v13

    .line 188
    iget-boolean v5, v2, Lqp0/r;->c:Z

    .line 189
    .line 190
    xor-int/2addr v5, v8

    .line 191
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 192
    .line 193
    .line 194
    move-result-object v14

    .line 195
    iget-boolean v5, v2, Lqp0/r;->b:Z

    .line 196
    .line 197
    xor-int/2addr v5, v8

    .line 198
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 199
    .line 200
    .line 201
    move-result-object v15

    .line 202
    iget-boolean v5, v2, Lqp0/r;->a:Z

    .line 203
    .line 204
    xor-int/2addr v5, v8

    .line 205
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 206
    .line 207
    .line 208
    move-result-object v16

    .line 209
    iget-boolean v2, v2, Lqp0/r;->d:Z

    .line 210
    .line 211
    xor-int/2addr v2, v8

    .line 212
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 213
    .line 214
    .line 215
    move-result-object v17

    .line 216
    invoke-direct/range {v12 .. v17}, Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerPreferencesDto;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 217
    .line 218
    .line 219
    goto :goto_5

    .line 220
    :cond_b
    move-object v12, v11

    .line 221
    :goto_5
    new-instance v2, Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;

    .line 222
    .line 223
    invoke-direct {v2, v7, v12}, Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;-><init>(Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerPreferencesDto;)V

    .line 224
    .line 225
    .line 226
    if-nez v10, :cond_c

    .line 227
    .line 228
    move-object v10, v11

    .line 229
    :cond_c
    new-instance v5, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;

    .line 230
    .line 231
    check-cast v3, Ljava/lang/String;

    .line 232
    .line 233
    check-cast v4, Ljava/lang/String;

    .line 234
    .line 235
    invoke-direct {v5, v3, v4, v10, v2}, Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/RoutePlannerDto;)V

    .line 236
    .line 237
    .line 238
    iput v9, v6, Li70/s;->e:I

    .line 239
    .line 240
    invoke-interface {v1, v5, v6}, Lcz/myskoda/api/bff_ai_assistant/v2/AiAssistantApi;->askAssistant(Lcz/myskoda/api/bff_ai_assistant/v2/AIAssistantRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v1

    .line 244
    if-ne v1, v0, :cond_d

    .line 245
    .line 246
    goto :goto_6

    .line 247
    :cond_d
    move-object v0, v1

    .line 248
    :goto_6
    return-object v0

    .line 249
    :pswitch_1
    move-object v11, v2

    .line 250
    check-cast v5, Li70/t;

    .line 251
    .line 252
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 253
    .line 254
    iget v0, v6, Li70/s;->e:I

    .line 255
    .line 256
    if-eqz v0, :cond_10

    .line 257
    .line 258
    if-eq v0, v8, :cond_f

    .line 259
    .line 260
    if-ne v0, v9, :cond_e

    .line 261
    .line 262
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    move-object/from16 v0, p1

    .line 266
    .line 267
    goto :goto_b

    .line 268
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 269
    .line 270
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 271
    .line 272
    .line 273
    throw v0

    .line 274
    :cond_f
    iget-object v0, v6, Li70/s;->h:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v0, Llx0/l;

    .line 277
    .line 278
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    move-object/from16 v1, p1

    .line 282
    .line 283
    goto :goto_7

    .line 284
    :cond_10
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    check-cast v4, Ll70/k;

    .line 288
    .line 289
    invoke-static {v4}, Li70/t;->a(Ll70/k;)Llx0/l;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    iget-object v1, v5, Li70/t;->b:Lti0/a;

    .line 294
    .line 295
    iput-object v0, v6, Li70/s;->h:Ljava/lang/Object;

    .line 296
    .line 297
    iput v8, v6, Li70/s;->e:I

    .line 298
    .line 299
    invoke-interface {v1, v6}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    if-ne v1, v10, :cond_11

    .line 304
    .line 305
    goto :goto_a

    .line 306
    :cond_11
    :goto_7
    check-cast v1, Lcz/myskoda/api/bff/v1/TripStatisticsApi;

    .line 307
    .line 308
    if-eqz v0, :cond_12

    .line 309
    .line 310
    iget-object v2, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 311
    .line 312
    check-cast v2, Ljava/time/OffsetDateTime;

    .line 313
    .line 314
    goto :goto_8

    .line 315
    :cond_12
    move-object v2, v11

    .line 316
    :goto_8
    if-eqz v0, :cond_13

    .line 317
    .line 318
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 319
    .line 320
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 321
    .line 322
    move-object v4, v0

    .line 323
    goto :goto_9

    .line 324
    :cond_13
    move-object v4, v11

    .line 325
    :goto_9
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    invoke-virtual {v0}, Ljava/time/ZoneId;->getId()Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v5

    .line 333
    check-cast v3, Ljava/lang/String;

    .line 334
    .line 335
    iput-object v11, v6, Li70/s;->h:Ljava/lang/Object;

    .line 336
    .line 337
    iput v9, v6, Li70/s;->e:I

    .line 338
    .line 339
    move-object v0, v1

    .line 340
    iget-object v1, v6, Li70/s;->f:Ljava/lang/String;

    .line 341
    .line 342
    move-object/from16 v18, v3

    .line 343
    .line 344
    move-object v3, v2

    .line 345
    move-object/from16 v2, v18

    .line 346
    .line 347
    invoke-interface/range {v0 .. v6}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->getSingleTripStatistics(Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v0

    .line 351
    if-ne v0, v10, :cond_14

    .line 352
    .line 353
    :goto_a
    move-object v0, v10

    .line 354
    :cond_14
    :goto_b
    return-object v0

    .line 355
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.class public final Ljh0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljava/lang/String;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p8, p0, Ljh0/d;->d:I

    iput-object p1, p0, Ljh0/d;->g:Ljava/lang/Object;

    iput-object p2, p0, Ljh0/d;->h:Ljava/lang/Object;

    iput-object p3, p0, Ljh0/d;->i:Ljava/lang/Object;

    iput-object p4, p0, Ljh0/d;->f:Ljava/lang/String;

    iput-object p5, p0, Ljh0/d;->j:Ljava/lang/Object;

    iput-object p6, p0, Ljh0/d;->k:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lrd0/n;Lod0/b0;Ljava/lang/String;Ljava/time/OffsetDateTime;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ljh0/d;->d:I

    .line 2
    iput-object p1, p0, Ljh0/d;->i:Ljava/lang/Object;

    iput-object p2, p0, Ljh0/d;->j:Ljava/lang/Object;

    iput-object p3, p0, Ljh0/d;->f:Ljava/lang/String;

    iput-object p4, p0, Ljh0/d;->k:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 11

    .line 1
    iget v0, p0, Ljh0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljh0/d;

    .line 7
    .line 8
    iget-object v0, p0, Ljh0/d;->g:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v0

    .line 11
    check-cast v2, Lyk0/n;

    .line 12
    .line 13
    iget-object v0, p0, Ljh0/d;->h:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v0

    .line 16
    check-cast v3, Lxj0/f;

    .line 17
    .line 18
    iget-object v0, p0, Ljh0/d;->i:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    check-cast v4, Lmk0/d;

    .line 22
    .line 23
    iget-object v0, p0, Ljh0/d;->j:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v6, v0

    .line 26
    check-cast v6, Ljava/util/UUID;

    .line 27
    .line 28
    iget-object v0, p0, Ljh0/d;->k:Ljava/lang/Object;

    .line 29
    .line 30
    move-object v7, v0

    .line 31
    check-cast v7, Ljava/util/List;

    .line 32
    .line 33
    const/4 v9, 0x2

    .line 34
    iget-object v5, p0, Ljh0/d;->f:Ljava/lang/String;

    .line 35
    .line 36
    move-object v8, p1

    .line 37
    invoke-direct/range {v1 .. v9}, Ljh0/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    return-object v1

    .line 41
    :pswitch_0
    move-object v7, p1

    .line 42
    new-instance v2, Ljh0/d;

    .line 43
    .line 44
    iget-object p1, p0, Ljh0/d;->i:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v3, p1

    .line 47
    check-cast v3, Lrd0/n;

    .line 48
    .line 49
    iget-object p1, p0, Ljh0/d;->j:Ljava/lang/Object;

    .line 50
    .line 51
    move-object v4, p1

    .line 52
    check-cast v4, Lod0/b0;

    .line 53
    .line 54
    iget-object p1, p0, Ljh0/d;->k:Ljava/lang/Object;

    .line 55
    .line 56
    move-object v6, p1

    .line 57
    check-cast v6, Ljava/time/OffsetDateTime;

    .line 58
    .line 59
    iget-object v5, p0, Ljh0/d;->f:Ljava/lang/String;

    .line 60
    .line 61
    invoke-direct/range {v2 .. v7}, Ljh0/d;-><init>(Lrd0/n;Lod0/b0;Ljava/lang/String;Ljava/time/OffsetDateTime;Lkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    return-object v2

    .line 65
    :pswitch_1
    move-object v7, p1

    .line 66
    new-instance v2, Ljh0/d;

    .line 67
    .line 68
    iget-object p1, p0, Ljh0/d;->g:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v3, p1

    .line 71
    check-cast v3, Ljh0/e;

    .line 72
    .line 73
    iget-object p1, p0, Ljh0/d;->h:Ljava/lang/Object;

    .line 74
    .line 75
    move-object v4, p1

    .line 76
    check-cast v4, Lmh0/a;

    .line 77
    .line 78
    iget-object p1, p0, Ljh0/d;->i:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v5, p1

    .line 81
    check-cast v5, Lmh0/c;

    .line 82
    .line 83
    iget-object p1, p0, Ljh0/d;->j:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p1, [B

    .line 86
    .line 87
    iget-object v0, p0, Ljh0/d;->k:Ljava/lang/Object;

    .line 88
    .line 89
    move-object v8, v0

    .line 90
    check-cast v8, Ljava/util/List;

    .line 91
    .line 92
    const/4 v10, 0x0

    .line 93
    iget-object v6, p0, Ljh0/d;->f:Ljava/lang/String;

    .line 94
    .line 95
    move-object v9, v7

    .line 96
    move-object v7, p1

    .line 97
    invoke-direct/range {v2 .. v10}, Ljh0/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 98
    .line 99
    .line 100
    return-object v2

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ljh0/d;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljh0/d;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljh0/d;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljh0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ljh0/d;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljh0/d;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljh0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Ljh0/d;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljh0/d;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Ljh0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 22

    .line 1
    move-object/from16 v8, p0

    .line 2
    .line 3
    iget v0, v8, Ljh0/d;->d:I

    .line 4
    .line 5
    iget-object v1, v8, Ljh0/d;->k:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v2, v8, Ljh0/d;->j:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v3, v8, Ljh0/d;->i:Ljava/lang/Object;

    .line 10
    .line 11
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 12
    .line 13
    const/4 v5, 0x1

    .line 14
    const/4 v6, 0x2

    .line 15
    const/4 v7, 0x0

    .line 16
    packed-switch v0, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    iget-object v0, v8, Ljh0/d;->h:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lxj0/f;

    .line 22
    .line 23
    sget-object v14, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    iget v9, v8, Ljh0/d;->e:I

    .line 26
    .line 27
    if-eqz v9, :cond_2

    .line 28
    .line 29
    if-eq v9, v5, :cond_1

    .line 30
    .line 31
    if-ne v9, v6, :cond_0

    .line 32
    .line 33
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    move-object/from16 v14, p1

    .line 37
    .line 38
    goto/16 :goto_3

    .line 39
    .line 40
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v0

    .line 46
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move-object/from16 v4, p1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object v4, v8, Ljh0/d;->g:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v4, Lyk0/n;

    .line 58
    .line 59
    iget-object v4, v4, Lyk0/n;->b:Lti0/a;

    .line 60
    .line 61
    iput v5, v8, Ljh0/d;->e:I

    .line 62
    .line 63
    invoke-interface {v4, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    if-ne v4, v14, :cond_3

    .line 68
    .line 69
    goto/16 :goto_3

    .line 70
    .line 71
    :cond_3
    :goto_0
    check-cast v4, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 72
    .line 73
    if-eqz v0, :cond_4

    .line 74
    .line 75
    iget-wide v9, v0, Lxj0/f;->a:D

    .line 76
    .line 77
    new-instance v5, Ljava/lang/Double;

    .line 78
    .line 79
    invoke-direct {v5, v9, v10}, Ljava/lang/Double;-><init>(D)V

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_4
    move-object v5, v7

    .line 84
    :goto_1
    if-eqz v0, :cond_5

    .line 85
    .line 86
    iget-wide v9, v0, Lxj0/f;->b:D

    .line 87
    .line 88
    new-instance v7, Ljava/lang/Double;

    .line 89
    .line 90
    invoke-direct {v7, v9, v10}, Ljava/lang/Double;-><init>(D)V

    .line 91
    .line 92
    .line 93
    :cond_5
    check-cast v3, Lmk0/d;

    .line 94
    .line 95
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    const-string v3, "LOCATION"

    .line 100
    .line 101
    packed-switch v0, :pswitch_data_1

    .line 102
    .line 103
    .line 104
    new-instance v0, La8/r0;

    .line 105
    .line 106
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 107
    .line 108
    .line 109
    throw v0

    .line 110
    :pswitch_0
    const-string v3, "RESTAURANT"

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :pswitch_1
    const-string v3, "PAY_GAS_STATION"

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :pswitch_2
    const-string v3, "GAS_STATION"

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :pswitch_3
    const-string v3, "PAY_PARKING_ZONE"

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :pswitch_4
    const-string v3, "PAY_PARKING"

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :pswitch_5
    const-string v3, "PARKING"

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :pswitch_6
    const-string v3, "CHARGING_STATION"

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :pswitch_7
    const-string v3, "SERVICE"

    .line 132
    .line 133
    :goto_2
    :pswitch_8
    check-cast v2, Ljava/util/UUID;

    .line 134
    .line 135
    move-object v10, v1

    .line 136
    check-cast v10, Ljava/util/List;

    .line 137
    .line 138
    iput v6, v8, Ljh0/d;->e:I

    .line 139
    .line 140
    iget-object v1, v8, Ljh0/d;->f:Ljava/lang/String;

    .line 141
    .line 142
    move-object v0, v4

    .line 143
    const/4 v4, 0x0

    .line 144
    move-object v6, v5

    .line 145
    const/4 v5, 0x0

    .line 146
    const/4 v8, 0x0

    .line 147
    const/4 v9, 0x0

    .line 148
    const/16 v12, 0x198

    .line 149
    .line 150
    const/4 v13, 0x0

    .line 151
    move-object v11, v3

    .line 152
    move-object v3, v2

    .line 153
    move-object v2, v11

    .line 154
    move-object/from16 v11, p0

    .line 155
    .line 156
    invoke-static/range {v0 .. v13}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getPlaceDetail$default(Lcz/myskoda/api/bff_maps/v3/MapsApi;Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    if-ne v0, v14, :cond_6

    .line 161
    .line 162
    goto :goto_3

    .line 163
    :cond_6
    move-object v14, v0

    .line 164
    :goto_3
    return-object v14

    .line 165
    :pswitch_9
    check-cast v3, Lrd0/n;

    .line 166
    .line 167
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 168
    .line 169
    iget v0, v8, Ljh0/d;->e:I

    .line 170
    .line 171
    if-eqz v0, :cond_9

    .line 172
    .line 173
    if-eq v0, v5, :cond_8

    .line 174
    .line 175
    if-ne v0, v6, :cond_7

    .line 176
    .line 177
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    move-object/from16 v0, p1

    .line 181
    .line 182
    goto/16 :goto_7

    .line 183
    .line 184
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 185
    .line 186
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    throw v0

    .line 190
    :cond_8
    iget-object v0, v8, Ljh0/d;->h:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 193
    .line 194
    iget-object v2, v8, Ljh0/d;->g:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast v2, Ljava/time/OffsetDateTime;

    .line 197
    .line 198
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    move-object v4, v2

    .line 202
    move-object/from16 v2, p1

    .line 203
    .line 204
    goto :goto_4

    .line 205
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    iget-object v0, v3, Lrd0/n;->b:Lrd0/c0;

    .line 209
    .line 210
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    const-string v10, "systemDefault(...)"

    .line 215
    .line 216
    invoke-static {v4, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    invoke-static {v0, v4}, Ljp/rb;->b(Lrd0/c0;Ljava/time/ZoneId;)Llx0/l;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    iget-object v4, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v4, Ljava/time/OffsetDateTime;

    .line 226
    .line 227
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 230
    .line 231
    check-cast v2, Lod0/b0;

    .line 232
    .line 233
    iget-object v2, v2, Lod0/b0;->b:Lti0/a;

    .line 234
    .line 235
    iput-object v4, v8, Ljh0/d;->g:Ljava/lang/Object;

    .line 236
    .line 237
    iput-object v0, v8, Ljh0/d;->h:Ljava/lang/Object;

    .line 238
    .line 239
    iput v5, v8, Ljh0/d;->e:I

    .line 240
    .line 241
    invoke-interface {v2, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v2

    .line 245
    if-ne v2, v9, :cond_a

    .line 246
    .line 247
    goto :goto_6

    .line 248
    :cond_a
    :goto_4
    check-cast v2, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 249
    .line 250
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 251
    .line 252
    .line 253
    move-result-object v10

    .line 254
    invoke-virtual {v10}, Ljava/time/ZoneId;->getId()Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v10

    .line 258
    const-string v11, "getId(...)"

    .line 259
    .line 260
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    iget-object v3, v3, Lrd0/n;->a:Lqr0/a;

    .line 264
    .line 265
    if-eqz v3, :cond_d

    .line 266
    .line 267
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 268
    .line 269
    .line 270
    move-result v3

    .line 271
    if-eqz v3, :cond_c

    .line 272
    .line 273
    if-ne v3, v5, :cond_b

    .line 274
    .line 275
    const-string v3, "DC"

    .line 276
    .line 277
    goto :goto_5

    .line 278
    :cond_b
    new-instance v0, La8/r0;

    .line 279
    .line 280
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 281
    .line 282
    .line 283
    throw v0

    .line 284
    :cond_c
    const-string v3, "AC"

    .line 285
    .line 286
    goto :goto_5

    .line 287
    :cond_d
    move-object v3, v7

    .line 288
    :goto_5
    check-cast v1, Ljava/time/OffsetDateTime;

    .line 289
    .line 290
    new-instance v5, Ljava/lang/Integer;

    .line 291
    .line 292
    const/16 v11, 0x14

    .line 293
    .line 294
    invoke-direct {v5, v11}, Ljava/lang/Integer;-><init>(I)V

    .line 295
    .line 296
    .line 297
    iput-object v7, v8, Ljh0/d;->g:Ljava/lang/Object;

    .line 298
    .line 299
    iput-object v7, v8, Ljh0/d;->h:Ljava/lang/Object;

    .line 300
    .line 301
    iput v6, v8, Ljh0/d;->e:I

    .line 302
    .line 303
    move-object v7, v5

    .line 304
    move-object v5, v4

    .line 305
    move-object v4, v1

    .line 306
    iget-object v1, v8, Ljh0/d;->f:Ljava/lang/String;

    .line 307
    .line 308
    move-object v6, v0

    .line 309
    move-object v0, v2

    .line 310
    move-object v2, v10

    .line 311
    invoke-interface/range {v0 .. v8}, Lcz/myskoda/api/bff/v1/ChargingApi;->getChargingHistory(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    if-ne v0, v9, :cond_e

    .line 316
    .line 317
    :goto_6
    move-object v0, v9

    .line 318
    :cond_e
    :goto_7
    return-object v0

    .line 319
    :pswitch_a
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 320
    .line 321
    iget v9, v8, Ljh0/d;->e:I

    .line 322
    .line 323
    if-eqz v9, :cond_11

    .line 324
    .line 325
    if-eq v9, v5, :cond_10

    .line 326
    .line 327
    if-ne v9, v6, :cond_f

    .line 328
    .line 329
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    move-object/from16 v0, p1

    .line 333
    .line 334
    goto/16 :goto_d

    .line 335
    .line 336
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 337
    .line 338
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 339
    .line 340
    .line 341
    throw v0

    .line 342
    :cond_10
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 343
    .line 344
    .line 345
    move-object/from16 v4, p1

    .line 346
    .line 347
    goto :goto_8

    .line 348
    :cond_11
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    iget-object v4, v8, Ljh0/d;->g:Ljava/lang/Object;

    .line 352
    .line 353
    check-cast v4, Ljh0/e;

    .line 354
    .line 355
    iget-object v4, v4, Ljh0/e;->b:Lti0/a;

    .line 356
    .line 357
    iput v5, v8, Ljh0/d;->e:I

    .line 358
    .line 359
    invoke-interface {v4, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 360
    .line 361
    .line 362
    move-result-object v4

    .line 363
    if-ne v4, v0, :cond_12

    .line 364
    .line 365
    goto/16 :goto_d

    .line 366
    .line 367
    :cond_12
    :goto_8
    check-cast v4, Lcz/myskoda/api/bff_feedbacks/v2/FeedbacksApi;

    .line 368
    .line 369
    iget-object v5, v8, Ljh0/d;->h:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v5, Lmh0/a;

    .line 372
    .line 373
    check-cast v3, Lmh0/c;

    .line 374
    .line 375
    new-instance v9, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;

    .line 376
    .line 377
    iget-object v10, v5, Lmh0/a;->a:Ljava/lang/String;

    .line 378
    .line 379
    iget v11, v5, Lmh0/a;->b:I

    .line 380
    .line 381
    iget-object v12, v5, Lmh0/a;->c:Lmh0/b;

    .line 382
    .line 383
    const-string v13, "<this>"

    .line 384
    .line 385
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 389
    .line 390
    .line 391
    move-result v12

    .line 392
    packed-switch v12, :pswitch_data_2

    .line 393
    .line 394
    .line 395
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->OTHER:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 396
    .line 397
    goto :goto_9

    .line 398
    :pswitch_b
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->APP_LOGS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 399
    .line 400
    goto :goto_9

    .line 401
    :pswitch_c
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->ENGINE_AND_TRANSMISSION:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 402
    .line 403
    goto :goto_9

    .line 404
    :pswitch_d
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->ASSISTANCE_SYSTEMS:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 405
    .line 406
    goto :goto_9

    .line 407
    :pswitch_e
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->DRIVING_AND_CHARGING:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 408
    .line 409
    goto :goto_9

    .line 410
    :pswitch_f
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->INFOTAINMENT:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 411
    .line 412
    goto :goto_9

    .line 413
    :pswitch_10
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->INTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 414
    .line 415
    goto :goto_9

    .line 416
    :pswitch_11
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->EXTERIOR:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 417
    .line 418
    goto :goto_9

    .line 419
    :pswitch_12
    sget-object v12, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;->MOBILE_APP:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;

    .line 420
    .line 421
    :goto_9
    iget-boolean v13, v5, Lmh0/a;->d:Z

    .line 422
    .line 423
    new-instance v14, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackMetadataDto;

    .line 424
    .line 425
    sget-object v16, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackMetadataDto$OperatingSystem;->ANDROID:Lcz/myskoda/api/bff_feedbacks/v2/FeedbackMetadataDto$OperatingSystem;

    .line 426
    .line 427
    iget-object v3, v3, Lmh0/c;->a:Ljava/lang/String;

    .line 428
    .line 429
    sget-object v18, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 430
    .line 431
    sget-object v19, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 432
    .line 433
    const-string v15, "8.8.0"

    .line 434
    .line 435
    move-object/from16 v17, v3

    .line 436
    .line 437
    invoke-direct/range {v14 .. v19}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackMetadataDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_feedbacks/v2/FeedbackMetadataDto$OperatingSystem;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    iget-object v3, v8, Ljh0/d;->f:Ljava/lang/String;

    .line 441
    .line 442
    if-nez v3, :cond_13

    .line 443
    .line 444
    move-object v15, v7

    .line 445
    goto :goto_a

    .line 446
    :cond_13
    move-object v15, v3

    .line 447
    :goto_a
    invoke-direct/range {v9 .. v15}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;-><init>(Ljava/lang/String;ILcz/myskoda/api/bff_feedbacks/v2/FeedbackDto$Category;ZLcz/myskoda/api/bff_feedbacks/v2/FeedbackMetadataDto;Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    sget-object v3, Ld01/y;->e:Ld01/y;

    .line 451
    .line 452
    const-string v3, "logs"

    .line 453
    .line 454
    const-string v5, "logs.zip"

    .line 455
    .line 456
    filled-new-array {v3, v5}, [Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v3

    .line 460
    invoke-static {v3, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 461
    .line 462
    .line 463
    move-result-object v3

    .line 464
    const-string v5, "form-data; name=\"%s\"; filename=\"%s"

    .line 465
    .line 466
    invoke-static {v5, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 467
    .line 468
    .line 469
    move-result-object v3

    .line 470
    const-string v10, "Content-Disposition"

    .line 471
    .line 472
    filled-new-array {v10, v3}, [Ljava/lang/String;

    .line 473
    .line 474
    .line 475
    move-result-object v3

    .line 476
    invoke-static {v3}, Ljp/te;->b([Ljava/lang/String;)Ld01/y;

    .line 477
    .line 478
    .line 479
    move-result-object v3

    .line 480
    sget-object v11, Ld01/r0;->Companion:Ld01/q0;

    .line 481
    .line 482
    check-cast v2, [B

    .line 483
    .line 484
    sget-object v12, Ld01/d0;->e:Lly0/n;

    .line 485
    .line 486
    const-string v12, "application/zip"

    .line 487
    .line 488
    invoke-static {v12}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 489
    .line 490
    .line 491
    move-result-object v12

    .line 492
    const/4 v13, 0x0

    .line 493
    const/4 v14, 0x6

    .line 494
    invoke-static {v11, v2, v12, v13, v14}, Ld01/q0;->c(Ld01/q0;[BLd01/d0;II)Ld01/p0;

    .line 495
    .line 496
    .line 497
    move-result-object v2

    .line 498
    const-string v11, "Content-Type"

    .line 499
    .line 500
    invoke-virtual {v3, v11}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 501
    .line 502
    .line 503
    move-result-object v12

    .line 504
    const-string v15, "Unexpected header: Content-Type"

    .line 505
    .line 506
    if-nez v12, :cond_1b

    .line 507
    .line 508
    const-string v12, "Content-Length"

    .line 509
    .line 510
    invoke-virtual {v3, v12}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 511
    .line 512
    .line 513
    move-result-object v16

    .line 514
    move-object/from16 v17, v7

    .line 515
    .line 516
    const-string v7, "Unexpected header: Content-Length"

    .line 517
    .line 518
    if-nez v16, :cond_1a

    .line 519
    .line 520
    new-instance v13, Ld01/e0;

    .line 521
    .line 522
    invoke-direct {v13, v3, v2}, Ld01/e0;-><init>(Ld01/y;Ld01/r0;)V

    .line 523
    .line 524
    .line 525
    check-cast v1, Ljava/util/List;

    .line 526
    .line 527
    if-eqz v1, :cond_18

    .line 528
    .line 529
    check-cast v1, Ljava/lang/Iterable;

    .line 530
    .line 531
    new-instance v2, Ljava/util/ArrayList;

    .line 532
    .line 533
    const/16 v3, 0xa

    .line 534
    .line 535
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 536
    .line 537
    .line 538
    move-result v3

    .line 539
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 540
    .line 541
    .line 542
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 543
    .line 544
    .line 545
    move-result-object v1

    .line 546
    const/4 v3, 0x0

    .line 547
    :goto_b
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 548
    .line 549
    .line 550
    move-result v16

    .line 551
    if-eqz v16, :cond_17

    .line 552
    .line 553
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    move-result-object v16

    .line 557
    add-int/lit8 v14, v3, 0x1

    .line 558
    .line 559
    if-ltz v3, :cond_16

    .line 560
    .line 561
    move-object/from16 v3, v16

    .line 562
    .line 563
    check-cast v3, [B

    .line 564
    .line 565
    sget-object v16, Ld01/y;->e:Ld01/y;

    .line 566
    .line 567
    const-string v6, "image"

    .line 568
    .line 569
    move-object/from16 v19, v1

    .line 570
    .line 571
    const-string v1, ".jpg"

    .line 572
    .line 573
    invoke-static {v6, v14, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 574
    .line 575
    .line 576
    move-result-object v1

    .line 577
    const-string v6, "images"

    .line 578
    .line 579
    filled-new-array {v6, v1}, [Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    move-result-object v1

    .line 583
    const/4 v6, 0x2

    .line 584
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 585
    .line 586
    .line 587
    move-result-object v1

    .line 588
    invoke-static {v5, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v1

    .line 592
    filled-new-array {v10, v1}, [Ljava/lang/String;

    .line 593
    .line 594
    .line 595
    move-result-object v1

    .line 596
    invoke-static {v1}, Ljp/te;->b([Ljava/lang/String;)Ld01/y;

    .line 597
    .line 598
    .line 599
    move-result-object v1

    .line 600
    sget-object v6, Ld01/r0;->Companion:Ld01/q0;

    .line 601
    .line 602
    sget-object v20, Ld01/d0;->e:Lly0/n;

    .line 603
    .line 604
    const-string v20, "image/jpeg"

    .line 605
    .line 606
    move-object/from16 v21, v5

    .line 607
    .line 608
    invoke-static/range {v20 .. v20}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 609
    .line 610
    .line 611
    move-result-object v5

    .line 612
    move-object/from16 v20, v10

    .line 613
    .line 614
    move/from16 p1, v14

    .line 615
    .line 616
    const/4 v10, 0x6

    .line 617
    const/4 v14, 0x0

    .line 618
    invoke-static {v6, v3, v5, v14, v10}, Ld01/q0;->c(Ld01/q0;[BLd01/d0;II)Ld01/p0;

    .line 619
    .line 620
    .line 621
    move-result-object v3

    .line 622
    invoke-virtual {v1, v11}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 623
    .line 624
    .line 625
    move-result-object v5

    .line 626
    if-nez v5, :cond_15

    .line 627
    .line 628
    invoke-virtual {v1, v12}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 629
    .line 630
    .line 631
    move-result-object v5

    .line 632
    if-nez v5, :cond_14

    .line 633
    .line 634
    new-instance v5, Ld01/e0;

    .line 635
    .line 636
    invoke-direct {v5, v1, v3}, Ld01/e0;-><init>(Ld01/y;Ld01/r0;)V

    .line 637
    .line 638
    .line 639
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 640
    .line 641
    .line 642
    move/from16 v3, p1

    .line 643
    .line 644
    move v14, v10

    .line 645
    move-object/from16 v1, v19

    .line 646
    .line 647
    move-object/from16 v10, v20

    .line 648
    .line 649
    move-object/from16 v5, v21

    .line 650
    .line 651
    const/4 v6, 0x2

    .line 652
    goto :goto_b

    .line 653
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 654
    .line 655
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 656
    .line 657
    .line 658
    throw v0

    .line 659
    :cond_15
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 660
    .line 661
    invoke-direct {v0, v15}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 662
    .line 663
    .line 664
    throw v0

    .line 665
    :cond_16
    invoke-static {}, Ljp/k1;->r()V

    .line 666
    .line 667
    .line 668
    throw v17

    .line 669
    :cond_17
    move-object v7, v2

    .line 670
    goto :goto_c

    .line 671
    :cond_18
    move-object/from16 v7, v17

    .line 672
    .line 673
    :goto_c
    iput v6, v8, Ljh0/d;->e:I

    .line 674
    .line 675
    invoke-interface {v4, v9, v13, v7, v8}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbacksApi;->createFeedback(Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;Ld01/e0;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 676
    .line 677
    .line 678
    move-result-object v1

    .line 679
    if-ne v1, v0, :cond_19

    .line 680
    .line 681
    goto :goto_d

    .line 682
    :cond_19
    move-object v0, v1

    .line 683
    :goto_d
    return-object v0

    .line 684
    :cond_1a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 685
    .line 686
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 687
    .line 688
    .line 689
    throw v0

    .line 690
    :cond_1b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 691
    .line 692
    invoke-direct {v0, v15}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 693
    .line 694
    .line 695
    throw v0

    .line 696
    nop

    .line 697
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
    .end packed-switch

    .line 698
    .line 699
    .line 700
    .line 701
    .line 702
    .line 703
    .line 704
    .line 705
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_8
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_8
    .end packed-switch

    .line 706
    .line 707
    .line 708
    .line 709
    .line 710
    .line 711
    .line 712
    .line 713
    .line 714
    .line 715
    .line 716
    .line 717
    .line 718
    .line 719
    .line 720
    .line 721
    .line 722
    .line 723
    .line 724
    .line 725
    .line 726
    .line 727
    .line 728
    .line 729
    .line 730
    .line 731
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
    .end packed-switch
.end method

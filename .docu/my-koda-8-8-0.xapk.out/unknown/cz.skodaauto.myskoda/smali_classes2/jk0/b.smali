.class public final Ljk0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljk0/c;

.field public final synthetic g:Lmk0/c;


# direct methods
.method public synthetic constructor <init>(Ljk0/c;Lmk0/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Ljk0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljk0/b;->f:Ljk0/c;

    .line 4
    .line 5
    iput-object p2, p0, Ljk0/b;->g:Lmk0/c;

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
    iget v0, p0, Ljk0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljk0/b;

    .line 7
    .line 8
    iget-object v1, p0, Ljk0/b;->g:Lmk0/c;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Ljk0/b;->f:Ljk0/c;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p1, v2}, Ljk0/b;-><init>(Ljk0/c;Lmk0/c;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ljk0/b;

    .line 18
    .line 19
    iget-object v1, p0, Ljk0/b;->g:Lmk0/c;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    iget-object p0, p0, Ljk0/b;->f:Ljk0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, v1, p1, v2}, Ljk0/b;-><init>(Ljk0/c;Lmk0/c;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ljk0/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljk0/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljk0/b;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljk0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Ljk0/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljk0/b;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljk0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 14

    .line 1
    iget v0, p0, Ljk0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ljk0/b;->e:I

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
    goto :goto_3

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
    iget-object p1, p0, Ljk0/b;->f:Ljk0/c;

    .line 38
    .line 39
    iget-object p1, p1, Ljk0/c;->b:Lti0/a;

    .line 40
    .line 41
    iput v3, p0, Ljk0/b;->e:I

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
    goto :goto_2

    .line 50
    :cond_3
    :goto_0
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 51
    .line 52
    iget-object v1, p0, Ljk0/b;->g:Lmk0/c;

    .line 53
    .line 54
    iget-object v3, v1, Lmk0/c;->a:Ljava/lang/String;

    .line 55
    .line 56
    if-nez v3, :cond_4

    .line 57
    .line 58
    const-string v3, ""

    .line 59
    .line 60
    :cond_4
    new-instance v4, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;

    .line 61
    .line 62
    iget-object v5, v1, Lmk0/c;->b:Lmk0/b;

    .line 63
    .line 64
    invoke-static {v5}, Llp/ac;->d(Lmk0/b;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    new-instance v6, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 69
    .line 70
    iget-object v7, v1, Lmk0/c;->c:Ljava/lang/String;

    .line 71
    .line 72
    iget-object v8, v1, Lmk0/c;->d:Lxj0/f;

    .line 73
    .line 74
    if-eqz v8, :cond_5

    .line 75
    .line 76
    new-instance v9, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 77
    .line 78
    iget-wide v10, v8, Lxj0/f;->a:D

    .line 79
    .line 80
    iget-wide v12, v8, Lxj0/f;->b:D

    .line 81
    .line 82
    invoke-direct {v9, v10, v11, v12, v13}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;-><init>(DD)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_5
    const/4 v9, 0x0

    .line 87
    :goto_1
    iget-object v8, v1, Lmk0/c;->e:Ljava/lang/String;

    .line 88
    .line 89
    iget-object v1, v1, Lmk0/c;->f:Ljava/lang/String;

    .line 90
    .line 91
    invoke-direct {v6, v7, v9, v8, v1}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-direct {v4, v5, v6}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;)V

    .line 95
    .line 96
    .line 97
    iput v2, p0, Ljk0/b;->e:I

    .line 98
    .line 99
    invoke-interface {p1, v3, v4, p0}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->updateFavouritePlace(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    if-ne p1, v0, :cond_6

    .line 104
    .line 105
    :goto_2
    move-object p1, v0

    .line 106
    :cond_6
    :goto_3
    return-object p1

    .line 107
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 108
    .line 109
    iget v1, p0, Ljk0/b;->e:I

    .line 110
    .line 111
    const/4 v2, 0x2

    .line 112
    const/4 v3, 0x1

    .line 113
    if-eqz v1, :cond_9

    .line 114
    .line 115
    if-eq v1, v3, :cond_8

    .line 116
    .line 117
    if-ne v1, v2, :cond_7

    .line 118
    .line 119
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 126
    .line 127
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0

    .line 131
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iget-object p1, p0, Ljk0/b;->f:Ljk0/c;

    .line 139
    .line 140
    iget-object p1, p1, Ljk0/c;->b:Lti0/a;

    .line 141
    .line 142
    iput v3, p0, Ljk0/b;->e:I

    .line 143
    .line 144
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    if-ne p1, v0, :cond_a

    .line 149
    .line 150
    goto :goto_6

    .line 151
    :cond_a
    :goto_4
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 152
    .line 153
    const-string v1, "<this>"

    .line 154
    .line 155
    iget-object v3, p0, Ljk0/b;->g:Lmk0/c;

    .line 156
    .line 157
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    new-instance v1, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;

    .line 161
    .line 162
    iget-object v4, v3, Lmk0/c;->b:Lmk0/b;

    .line 163
    .line 164
    invoke-static {v4}, Llp/ac;->d(Lmk0/b;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    iget-object v5, v3, Lmk0/c;->c:Ljava/lang/String;

    .line 169
    .line 170
    iget-object v6, v3, Lmk0/c;->d:Lxj0/f;

    .line 171
    .line 172
    if-eqz v6, :cond_b

    .line 173
    .line 174
    new-instance v7, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 175
    .line 176
    iget-wide v8, v6, Lxj0/f;->a:D

    .line 177
    .line 178
    iget-wide v10, v6, Lxj0/f;->b:D

    .line 179
    .line 180
    invoke-direct {v7, v8, v9, v10, v11}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;-><init>(DD)V

    .line 181
    .line 182
    .line 183
    goto :goto_5

    .line 184
    :cond_b
    const/4 v7, 0x0

    .line 185
    :goto_5
    iget-object v6, v3, Lmk0/c;->f:Ljava/lang/String;

    .line 186
    .line 187
    iget-object v3, v3, Lmk0/c;->e:Ljava/lang/String;

    .line 188
    .line 189
    new-instance v8, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 190
    .line 191
    invoke-direct {v8, v5, v7, v3, v6}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    invoke-direct {v1, v4, v8}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;)V

    .line 195
    .line 196
    .line 197
    iput v2, p0, Ljk0/b;->e:I

    .line 198
    .line 199
    invoke-interface {p1, v1, p0}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->createFavouritePlace(Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    if-ne p1, v0, :cond_c

    .line 204
    .line 205
    :goto_6
    move-object p1, v0

    .line 206
    :cond_c
    :goto_7
    return-object p1

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

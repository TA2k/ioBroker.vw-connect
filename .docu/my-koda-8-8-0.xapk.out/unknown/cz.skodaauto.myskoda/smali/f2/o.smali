.class public final Lf2/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:F

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(FLc1/j;Lkotlin/jvm/internal/c0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lf2/o;->d:I

    .line 1
    iput p1, p0, Lf2/o;->f:F

    iput-object p2, p0, Lf2/o;->h:Ljava/lang/Object;

    iput-object p3, p0, Lf2/o;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;FLjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p6, p0, Lf2/o;->d:I

    iput-object p1, p0, Lf2/o;->g:Ljava/lang/Object;

    iput p2, p0, Lf2/o;->f:F

    iput-object p3, p0, Lf2/o;->h:Ljava/lang/Object;

    iput-object p4, p0, Lf2/o;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lkn/c0;Lb1/x0;Lc1/j;FLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lf2/o;->d:I

    .line 3
    iput-object p1, p0, Lf2/o;->g:Ljava/lang/Object;

    iput-object p2, p0, Lf2/o;->h:Ljava/lang/Object;

    iput-object p3, p0, Lf2/o;->i:Ljava/lang/Object;

    iput p4, p0, Lf2/o;->f:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    iget v0, p0, Lf2/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lf2/o;

    .line 7
    .line 8
    iget-object p1, p0, Lf2/o;->g:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    check-cast v2, Lxj0/y;

    .line 12
    .line 13
    iget-object p1, p0, Lf2/o;->h:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, p1

    .line 16
    check-cast v4, Lay0/a;

    .line 17
    .line 18
    iget-object p1, p0, Lf2/o;->i:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v5, p1

    .line 21
    check-cast v5, Luu/g;

    .line 22
    .line 23
    const/4 v7, 0x3

    .line 24
    iget v3, p0, Lf2/o;->f:F

    .line 25
    .line 26
    move-object v6, p2

    .line 27
    invoke-direct/range {v1 .. v7}, Lf2/o;-><init>(Ljava/lang/Object;FLjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    return-object v1

    .line 31
    :pswitch_0
    move-object v7, p2

    .line 32
    new-instance v2, Lf2/o;

    .line 33
    .line 34
    iget-object p1, p0, Lf2/o;->g:Ljava/lang/Object;

    .line 35
    .line 36
    move-object v3, p1

    .line 37
    check-cast v3, Lkn/c0;

    .line 38
    .line 39
    iget-object p1, p0, Lf2/o;->h:Ljava/lang/Object;

    .line 40
    .line 41
    move-object v4, p1

    .line 42
    check-cast v4, Lb1/x0;

    .line 43
    .line 44
    iget-object p1, p0, Lf2/o;->i:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v5, p1

    .line 47
    check-cast v5, Lc1/j;

    .line 48
    .line 49
    iget v6, p0, Lf2/o;->f:F

    .line 50
    .line 51
    invoke-direct/range {v2 .. v7}, Lf2/o;-><init>(Lkn/c0;Lb1/x0;Lc1/j;FLkotlin/coroutines/Continuation;)V

    .line 52
    .line 53
    .line 54
    return-object v2

    .line 55
    :pswitch_1
    move-object v7, p2

    .line 56
    new-instance p2, Lf2/o;

    .line 57
    .line 58
    iget-object v0, p0, Lf2/o;->h:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Lc1/j;

    .line 61
    .line 62
    iget-object v1, p0, Lf2/o;->i:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v1, Lkotlin/jvm/internal/c0;

    .line 65
    .line 66
    iget p0, p0, Lf2/o;->f:F

    .line 67
    .line 68
    invoke-direct {p2, p0, v0, v1, v7}, Lf2/o;-><init>(FLc1/j;Lkotlin/jvm/internal/c0;Lkotlin/coroutines/Continuation;)V

    .line 69
    .line 70
    .line 71
    iput-object p1, p2, Lf2/o;->g:Ljava/lang/Object;

    .line 72
    .line 73
    return-object p2

    .line 74
    :pswitch_2
    move-object v7, p2

    .line 75
    new-instance v2, Lf2/o;

    .line 76
    .line 77
    iget-object p1, p0, Lf2/o;->g:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v3, p1

    .line 80
    check-cast v3, Lc1/c;

    .line 81
    .line 82
    iget-object p1, p0, Lf2/o;->h:Ljava/lang/Object;

    .line 83
    .line 84
    move-object v5, p1

    .line 85
    check-cast v5, Lf2/p;

    .line 86
    .line 87
    iget-object p1, p0, Lf2/o;->i:Ljava/lang/Object;

    .line 88
    .line 89
    move-object v6, p1

    .line 90
    check-cast v6, Li1/k;

    .line 91
    .line 92
    const/4 v8, 0x0

    .line 93
    iget v4, p0, Lf2/o;->f:F

    .line 94
    .line 95
    invoke-direct/range {v2 .. v8}, Lf2/o;-><init>(Ljava/lang/Object;FLjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 96
    .line 97
    .line 98
    return-object v2

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lf2/o;->d:I

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
    invoke-virtual {p0, p1, p2}, Lf2/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lf2/o;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lf2/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lf2/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lf2/o;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lf2/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lg1/e2;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lf2/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lf2/o;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lf2/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lf2/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lf2/o;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lf2/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lf2/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lf2/o;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto/16 :goto_1

    .line 19
    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object p1, p0, Lf2/o;->g:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p1, Lxj0/y;

    .line 34
    .line 35
    iget v1, p0, Lf2/o;->f:F

    .line 36
    .line 37
    invoke-static {v1}, Lxf0/i0;->O(F)I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    const-string v3, "<this>"

    .line 42
    .line 43
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    instance-of v3, p1, Lxj0/v;

    .line 47
    .line 48
    if-eqz v3, :cond_2

    .line 49
    .line 50
    new-instance v3, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 51
    .line 52
    new-instance v4, Lcom/google/android/gms/maps/model/LatLng;

    .line 53
    .line 54
    check-cast p1, Lxj0/v;

    .line 55
    .line 56
    iget-object v5, p1, Lxj0/v;->a:Lxj0/f;

    .line 57
    .line 58
    iget-wide v6, v5, Lxj0/f;->a:D

    .line 59
    .line 60
    iget-wide v8, v5, Lxj0/f;->b:D

    .line 61
    .line 62
    invoke-direct {v4, v6, v7, v8, v9}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 63
    .line 64
    .line 65
    new-instance v5, Lcom/google/android/gms/maps/model/LatLng;

    .line 66
    .line 67
    iget-object p1, p1, Lxj0/v;->b:Lxj0/f;

    .line 68
    .line 69
    iget-wide v6, p1, Lxj0/f;->a:D

    .line 70
    .line 71
    iget-wide v8, p1, Lxj0/f;->b:D

    .line 72
    .line 73
    invoke-direct {v5, v6, v7, v8, v9}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 74
    .line 75
    .line 76
    invoke-direct {v3, v4, v5}, Lcom/google/android/gms/maps/model/LatLngBounds;-><init>(Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 77
    .line 78
    .line 79
    invoke-static {v3, v1}, Ljp/wf;->d(Lcom/google/android/gms/maps/model/LatLngBounds;I)Lpv/g;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    goto :goto_0

    .line 84
    :cond_2
    instance-of v1, p1, Lxj0/x;

    .line 85
    .line 86
    if-eqz v1, :cond_4

    .line 87
    .line 88
    new-instance v1, Lcom/google/android/gms/maps/model/LatLng;

    .line 89
    .line 90
    check-cast p1, Lxj0/x;

    .line 91
    .line 92
    iget-object v3, p1, Lxj0/x;->a:Lxj0/f;

    .line 93
    .line 94
    iget-wide v4, v3, Lxj0/f;->a:D

    .line 95
    .line 96
    iget-wide v6, v3, Lxj0/f;->b:D

    .line 97
    .line 98
    invoke-direct {v1, v4, v5, v6, v7}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 99
    .line 100
    .line 101
    iget p1, p1, Lxj0/x;->b:F

    .line 102
    .line 103
    const/4 v3, 0x0

    .line 104
    cmpl-float v4, p1, v3

    .line 105
    .line 106
    if-lez v4, :cond_3

    .line 107
    .line 108
    new-instance v4, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 109
    .line 110
    invoke-direct {v4, v1, p1, v3, v3}, Lcom/google/android/gms/maps/model/CameraPosition;-><init>(Lcom/google/android/gms/maps/model/LatLng;FFF)V

    .line 111
    .line 112
    .line 113
    invoke-static {v4}, Ljp/wf;->b(Lcom/google/android/gms/maps/model/CameraPosition;)Lpv/g;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    goto :goto_0

    .line 118
    :cond_3
    invoke-static {v1}, Ljp/wf;->c(Lcom/google/android/gms/maps/model/LatLng;)Lpv/g;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    goto :goto_0

    .line 123
    :cond_4
    const/4 p1, 0x0

    .line 124
    :goto_0
    if-eqz p1, :cond_5

    .line 125
    .line 126
    iget-object v1, p0, Lf2/o;->i:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v1, Luu/g;

    .line 129
    .line 130
    iput v2, p0, Lf2/o;->e:I

    .line 131
    .line 132
    const v2, 0x7fffffff

    .line 133
    .line 134
    .line 135
    invoke-virtual {v1, p1, v2, p0}, Luu/g;->b(Lpv/g;ILrx0/c;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    if-ne p1, v0, :cond_5

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_5
    :goto_1
    iget-object p0, p0, Lf2/o;->h:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast p0, Lay0/a;

    .line 145
    .line 146
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    :goto_2
    return-object v0

    .line 152
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 153
    .line 154
    iget v1, p0, Lf2/o;->e:I

    .line 155
    .line 156
    const/4 v2, 0x1

    .line 157
    if-eqz v1, :cond_7

    .line 158
    .line 159
    if-ne v1, v2, :cond_6

    .line 160
    .line 161
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 166
    .line 167
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 168
    .line 169
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p0

    .line 173
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    iget-object p1, p0, Lf2/o;->g:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast p1, Lkn/c0;

    .line 179
    .line 180
    iget-object v3, p1, Lkn/c0;->f:Lc1/c;

    .line 181
    .line 182
    iget-object p1, p0, Lf2/o;->h:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast p1, Lb1/x0;

    .line 185
    .line 186
    iget p1, p1, Lb1/x0;->d:F

    .line 187
    .line 188
    new-instance v4, Ljava/lang/Float;

    .line 189
    .line 190
    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    .line 191
    .line 192
    .line 193
    iget-object p1, p0, Lf2/o;->i:Ljava/lang/Object;

    .line 194
    .line 195
    move-object v5, p1

    .line 196
    check-cast v5, Lc1/j;

    .line 197
    .line 198
    new-instance v6, Ljava/lang/Float;

    .line 199
    .line 200
    iget p1, p0, Lf2/o;->f:F

    .line 201
    .line 202
    invoke-direct {v6, p1}, Ljava/lang/Float;-><init>(F)V

    .line 203
    .line 204
    .line 205
    iput v2, p0, Lf2/o;->e:I

    .line 206
    .line 207
    const/4 v7, 0x0

    .line 208
    const/16 v9, 0x8

    .line 209
    .line 210
    move-object v8, p0

    .line 211
    invoke-static/range {v3 .. v9}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    if-ne p0, v0, :cond_8

    .line 216
    .line 217
    goto :goto_4

    .line 218
    :cond_8
    :goto_3
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 219
    .line 220
    :goto_4
    return-object v0

    .line 221
    :pswitch_1
    move-object v5, p0

    .line 222
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 223
    .line 224
    iget v0, v5, Lf2/o;->e:I

    .line 225
    .line 226
    const/4 v1, 0x1

    .line 227
    if-eqz v0, :cond_a

    .line 228
    .line 229
    if-ne v0, v1, :cond_9

    .line 230
    .line 231
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    goto :goto_5

    .line 235
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 236
    .line 237
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 238
    .line 239
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    throw p0

    .line 243
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    iget-object p1, v5, Lf2/o;->g:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast p1, Lg1/e2;

    .line 249
    .line 250
    iget-object v0, v5, Lf2/o;->h:Ljava/lang/Object;

    .line 251
    .line 252
    move-object v3, v0

    .line 253
    check-cast v3, Lc1/j;

    .line 254
    .line 255
    iget-object v0, v5, Lf2/o;->i:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v0, Lkotlin/jvm/internal/c0;

    .line 258
    .line 259
    new-instance v4, Ld90/m;

    .line 260
    .line 261
    const/16 v2, 0x11

    .line 262
    .line 263
    invoke-direct {v4, v2, v0, p1}, Ld90/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    iput v1, v5, Lf2/o;->e:I

    .line 267
    .line 268
    const/4 v1, 0x0

    .line 269
    iget v2, v5, Lf2/o;->f:F

    .line 270
    .line 271
    const/4 v6, 0x4

    .line 272
    invoke-static/range {v1 .. v6}, Lc1/d;->e(FFLc1/j;Lay0/n;Lrx0/i;I)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object p1

    .line 276
    if-ne p1, p0, :cond_b

    .line 277
    .line 278
    goto :goto_6

    .line 279
    :cond_b
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 280
    .line 281
    :goto_6
    return-object p0

    .line 282
    :pswitch_2
    move-object v5, p0

    .line 283
    iget-object p0, v5, Lf2/o;->h:Ljava/lang/Object;

    .line 284
    .line 285
    check-cast p0, Lf2/p;

    .line 286
    .line 287
    iget-object v0, v5, Lf2/o;->g:Ljava/lang/Object;

    .line 288
    .line 289
    check-cast v0, Lc1/c;

    .line 290
    .line 291
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 292
    .line 293
    iget v2, v5, Lf2/o;->e:I

    .line 294
    .line 295
    const/4 v3, 0x2

    .line 296
    if-eqz v2, :cond_e

    .line 297
    .line 298
    const/4 p0, 0x1

    .line 299
    if-eq v2, p0, :cond_d

    .line 300
    .line 301
    if-ne v2, v3, :cond_c

    .line 302
    .line 303
    goto :goto_7

    .line 304
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 305
    .line 306
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 307
    .line 308
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    throw p0

    .line 312
    :cond_d
    :goto_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    goto :goto_9

    .line 316
    :cond_e
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 317
    .line 318
    .line 319
    iget-object p1, v0, Lc1/c;->e:Ll2/j1;

    .line 320
    .line 321
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object p1

    .line 325
    check-cast p1, Lt4/f;

    .line 326
    .line 327
    iget p1, p1, Lt4/f;->d:F

    .line 328
    .line 329
    iget v2, v5, Lf2/o;->f:F

    .line 330
    .line 331
    invoke-static {p1, v2}, Lt4/f;->a(FF)Z

    .line 332
    .line 333
    .line 334
    move-result p1

    .line 335
    if-nez p1, :cond_12

    .line 336
    .line 337
    iget-object p1, v0, Lc1/c;->e:Ll2/j1;

    .line 338
    .line 339
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object p1

    .line 343
    check-cast p1, Lt4/f;

    .line 344
    .line 345
    iget p1, p1, Lt4/f;->d:F

    .line 346
    .line 347
    iget v4, p0, Lf2/p;->b:F

    .line 348
    .line 349
    invoke-static {p1, v4}, Lt4/f;->a(FF)Z

    .line 350
    .line 351
    .line 352
    move-result v4

    .line 353
    if-eqz v4, :cond_f

    .line 354
    .line 355
    new-instance p0, Li1/n;

    .line 356
    .line 357
    const-wide/16 v6, 0x0

    .line 358
    .line 359
    invoke-direct {p0, v6, v7}, Li1/n;-><init>(J)V

    .line 360
    .line 361
    .line 362
    goto :goto_8

    .line 363
    :cond_f
    iget v4, p0, Lf2/p;->c:F

    .line 364
    .line 365
    invoke-static {p1, v4}, Lt4/f;->a(FF)Z

    .line 366
    .line 367
    .line 368
    move-result v4

    .line 369
    if-eqz v4, :cond_10

    .line 370
    .line 371
    new-instance p0, Li1/i;

    .line 372
    .line 373
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 374
    .line 375
    .line 376
    goto :goto_8

    .line 377
    :cond_10
    iget p0, p0, Lf2/p;->d:F

    .line 378
    .line 379
    invoke-static {p1, p0}, Lt4/f;->a(FF)Z

    .line 380
    .line 381
    .line 382
    move-result p0

    .line 383
    if-eqz p0, :cond_11

    .line 384
    .line 385
    new-instance p0, Li1/e;

    .line 386
    .line 387
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 388
    .line 389
    .line 390
    goto :goto_8

    .line 391
    :cond_11
    const/4 p0, 0x0

    .line 392
    :goto_8
    iget-object p1, v5, Lf2/o;->i:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast p1, Li1/k;

    .line 395
    .line 396
    iput v3, v5, Lf2/o;->e:I

    .line 397
    .line 398
    invoke-static {v0, v2, p0, p1, v5}, Lf2/x;->a(Lc1/c;FLi1/k;Li1/k;Lrx0/c;)Ljava/lang/Object;

    .line 399
    .line 400
    .line 401
    move-result-object p0

    .line 402
    if-ne p0, v1, :cond_12

    .line 403
    .line 404
    goto :goto_a

    .line 405
    :cond_12
    :goto_9
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 406
    .line 407
    :goto_a
    return-object v1

    .line 408
    nop

    .line 409
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

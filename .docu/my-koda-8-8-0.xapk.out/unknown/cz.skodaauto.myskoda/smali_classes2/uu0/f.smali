.class public final Luu0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Luu0/x;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Luu0/x;I)V
    .locals 0

    .line 1
    iput p3, p0, Luu0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luu0/f;->e:Lvy0/b0;

    .line 4
    .line 5
    iput-object p2, p0, Luu0/f;->f:Luu0/x;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public b(Lfp0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Luu0/f;->f:Luu0/x;

    .line 2
    .line 3
    iget-object v1, v0, Luu0/x;->U:Lk70/q0;

    .line 4
    .line 5
    instance-of v2, p2, Luu0/k;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, p2

    .line 10
    check-cast v2, Luu0/k;

    .line 11
    .line 12
    iget v3, v2, Luu0/k;->g:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Luu0/k;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Luu0/k;

    .line 25
    .line 26
    invoke-direct {v2, p0, p2}, Luu0/k;-><init>(Luu0/f;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p2, v2, Luu0/k;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Luu0/k;->g:I

    .line 34
    .line 35
    iget-object p0, p0, Luu0/f;->e:Lvy0/b0;

    .line 36
    .line 37
    const/4 v5, 0x2

    .line 38
    const/4 v6, 0x1

    .line 39
    if-eqz v4, :cond_3

    .line 40
    .line 41
    if-eq v4, v6, :cond_2

    .line 42
    .line 43
    if-ne v4, v5, :cond_1

    .line 44
    .line 45
    iget-object p1, v2, Luu0/k;->d:Lfp0/d;

    .line 46
    .line 47
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    iget-object p1, v2, Luu0/k;->d:Lfp0/d;

    .line 60
    .line 61
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    new-instance p2, Luu0/j;

    .line 69
    .line 70
    const/4 v4, 0x0

    .line 71
    invoke-direct {p2, p1, v4}, Luu0/j;-><init>(Lfp0/d;I)V

    .line 72
    .line 73
    .line 74
    invoke-static {p0, p2}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 75
    .line 76
    .line 77
    iget-object p2, v0, Luu0/x;->T:Lep0/l;

    .line 78
    .line 79
    iput-object p1, v2, Luu0/k;->d:Lfp0/d;

    .line 80
    .line 81
    iput v6, v2, Luu0/k;->g:I

    .line 82
    .line 83
    invoke-virtual {p2, p1, v2}, Lep0/l;->b(Lfp0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    if-ne p2, v3, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    :goto_1
    iget-object p2, v0, Luu0/x;->E:Lrq0/f;

    .line 91
    .line 92
    new-instance v0, Lsq0/c;

    .line 93
    .line 94
    new-instance v4, Ljava/lang/Integer;

    .line 95
    .line 96
    const v7, 0x7f120370

    .line 97
    .line 98
    .line 99
    invoke-direct {v4, v7}, Ljava/lang/Integer;-><init>(I)V

    .line 100
    .line 101
    .line 102
    const/4 v7, 0x4

    .line 103
    const v8, 0x7f12023a

    .line 104
    .line 105
    .line 106
    invoke-direct {v0, v8, v7, v4}, Lsq0/c;-><init>(IILjava/lang/Integer;)V

    .line 107
    .line 108
    .line 109
    iput-object p1, v2, Luu0/k;->d:Lfp0/d;

    .line 110
    .line 111
    iput v5, v2, Luu0/k;->g:I

    .line 112
    .line 113
    const/4 v4, 0x0

    .line 114
    invoke-virtual {p2, v0, v4, v2}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    if-ne p2, v3, :cond_5

    .line 119
    .line 120
    :goto_2
    return-object v3

    .line 121
    :cond_5
    :goto_3
    check-cast p2, Lsq0/d;

    .line 122
    .line 123
    sget-object v0, Lsq0/d;->d:Lsq0/d;

    .line 124
    .line 125
    if-ne p2, v0, :cond_8

    .line 126
    .line 127
    new-instance p2, Luu0/j;

    .line 128
    .line 129
    const/4 v0, 0x1

    .line 130
    invoke-direct {p2, p1, v0}, Luu0/j;-><init>(Lfp0/d;I)V

    .line 131
    .line 132
    .line 133
    invoke-static {p0, p2}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    if-eqz p0, :cond_7

    .line 141
    .line 142
    if-ne p0, v6, :cond_6

    .line 143
    .line 144
    sget-object p0, Ll70/h;->f:Ll70/h;

    .line 145
    .line 146
    invoke-virtual {v1, p0}, Lk70/q0;->a(Ll70/h;)V

    .line 147
    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_6
    new-instance p0, La8/r0;

    .line 151
    .line 152
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 153
    .line 154
    .line 155
    throw p0

    .line 156
    :cond_7
    sget-object p0, Ll70/h;->d:Ll70/h;

    .line 157
    .line 158
    invoke-virtual {v1, p0}, Lk70/q0;->a(Ll70/h;)V

    .line 159
    .line 160
    .line 161
    :cond_8
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 162
    .line 163
    return-object p0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Luu0/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lfp0/d;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    invoke-virtual {v0, v1, v2}, Luu0/f;->b(Lfp0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    return-object v0

    .line 19
    :pswitch_0
    move-object/from16 v1, p1

    .line 20
    .line 21
    check-cast v1, Lra0/c;

    .line 22
    .line 23
    sget-object v2, Lra0/c;->d:Lra0/c;

    .line 24
    .line 25
    iget-object v3, v0, Luu0/f;->f:Luu0/x;

    .line 26
    .line 27
    if-ne v1, v2, :cond_0

    .line 28
    .line 29
    new-instance v2, Luu0/e;

    .line 30
    .line 31
    const/4 v4, 0x5

    .line 32
    const/4 v5, 0x0

    .line 33
    invoke-direct {v2, v3, v5, v4}, Luu0/e;-><init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    const/4 v4, 0x3

    .line 37
    iget-object v0, v0, Luu0/f;->e:Lvy0/b0;

    .line 38
    .line 39
    invoke-static {v0, v5, v5, v2, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 40
    .line 41
    .line 42
    :cond_0
    sget-object v0, Luu0/x;->q1:Ljava/util/List;

    .line 43
    .line 44
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Luu0/r;

    .line 49
    .line 50
    const/16 v21, 0x0

    .line 51
    .line 52
    const v22, 0x1bffff

    .line 53
    .line 54
    .line 55
    const/4 v2, 0x0

    .line 56
    move-object v4, v3

    .line 57
    const/4 v3, 0x0

    .line 58
    move-object v5, v4

    .line 59
    const/4 v4, 0x0

    .line 60
    move-object v6, v5

    .line 61
    const/4 v5, 0x0

    .line 62
    move-object v7, v6

    .line 63
    const/4 v6, 0x0

    .line 64
    move-object v8, v7

    .line 65
    const/4 v7, 0x0

    .line 66
    move-object v9, v8

    .line 67
    const/4 v8, 0x0

    .line 68
    move-object v10, v9

    .line 69
    const/4 v9, 0x0

    .line 70
    move-object v11, v10

    .line 71
    const/4 v10, 0x0

    .line 72
    move-object v12, v11

    .line 73
    const/4 v11, 0x0

    .line 74
    move-object v13, v12

    .line 75
    const/4 v12, 0x0

    .line 76
    move-object v14, v13

    .line 77
    const/4 v13, 0x0

    .line 78
    move-object v15, v14

    .line 79
    const/4 v14, 0x0

    .line 80
    move-object/from16 v16, v15

    .line 81
    .line 82
    const/4 v15, 0x0

    .line 83
    move-object/from16 v17, v16

    .line 84
    .line 85
    const/16 v16, 0x0

    .line 86
    .line 87
    move-object/from16 v18, v17

    .line 88
    .line 89
    const/16 v17, 0x0

    .line 90
    .line 91
    move-object/from16 v19, v18

    .line 92
    .line 93
    const/16 v18, 0x0

    .line 94
    .line 95
    const/16 v20, 0x0

    .line 96
    .line 97
    move-object/from16 v23, v1

    .line 98
    .line 99
    move-object v1, v0

    .line 100
    move-object/from16 v0, v19

    .line 101
    .line 102
    move-object/from16 v19, v23

    .line 103
    .line 104
    invoke-static/range {v1 .. v22}, Luu0/r;->a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 109
    .line 110
    .line 111
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object v0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

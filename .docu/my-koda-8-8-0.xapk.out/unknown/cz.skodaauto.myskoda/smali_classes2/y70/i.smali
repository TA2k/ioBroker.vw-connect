.class public final synthetic Ly70/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/o;


# direct methods
.method public synthetic constructor <init>(Ly70/o;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/i;->e:Ly70/o;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()Llx0/e;
    .locals 11

    .line 1
    iget v0, p0, Ly70/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onCzechRequestBookingUrlResult(Lcz/skodaauto/myskoda/library/data/infrastructure/ResultData;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Ly70/o;

    .line 13
    .line 14
    iget-object v5, p0, Ly70/i;->e:Ly70/o;

    .line 15
    .line 16
    const-string v6, "onCzechRequestBookingUrlResult"

    .line 17
    .line 18
    invoke-direct/range {v1 .. v7}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    new-instance v2, Lkotlin/jvm/internal/a;

    .line 23
    .line 24
    const-string v8, "onEncodedUrlResult(Lcz/skodaauto/myskoda/library/data/infrastructure/ResultData;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Ly70/o;

    .line 29
    .line 30
    iget-object v6, p0, Ly70/i;->e:Ly70/o;

    .line 31
    .line 32
    const-string v7, "onEncodedUrlResult"

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    :pswitch_1
    new-instance v3, Lkotlin/jvm/internal/a;

    .line 39
    .line 40
    const-string v9, "onCzechRequestBookingUrlResult(Lcz/skodaauto/myskoda/library/data/infrastructure/ResultData;)V"

    .line 41
    .line 42
    const/4 v5, 0x4

    .line 43
    const/4 v4, 0x2

    .line 44
    const-class v6, Ly70/o;

    .line 45
    .line 46
    iget-object v7, p0, Ly70/i;->e:Ly70/o;

    .line 47
    .line 48
    const-string v8, "onCzechRequestBookingUrlResult"

    .line 49
    .line 50
    invoke-direct/range {v3 .. v9}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return-object v3

    .line 54
    :pswitch_2
    new-instance v4, Lkotlin/jvm/internal/k;

    .line 55
    .line 56
    const-string v10, "onServiceData(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 57
    .line 58
    const/4 v6, 0x0

    .line 59
    const/4 v5, 0x2

    .line 60
    const-class v7, Ly70/o;

    .line 61
    .line 62
    iget-object v8, p0, Ly70/i;->e:Ly70/o;

    .line 63
    .line 64
    const-string v9, "onServiceData"

    .line 65
    .line 66
    invoke-direct/range {v4 .. v10}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-object v4

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Ly70/i;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Ly70/i;->e:Ly70/o;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p1, Lne0/t;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ly70/o;->l(Lne0/t;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    return-object v1

    .line 18
    :pswitch_0
    check-cast p1, Lne0/t;

    .line 19
    .line 20
    instance-of p2, p1, Lne0/c;

    .line 21
    .line 22
    if-eqz p2, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    move-object v2, p2

    .line 29
    check-cast v2, Ly70/k;

    .line 30
    .line 31
    check-cast p1, Lne0/c;

    .line 32
    .line 33
    iget-object p2, p0, Ly70/o;->n:Lij0/a;

    .line 34
    .line 35
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    const/4 v9, 0x0

    .line 40
    const/16 v10, 0x7e

    .line 41
    .line 42
    const/4 v4, 0x0

    .line 43
    const/4 v5, 0x0

    .line 44
    const/4 v6, 0x0

    .line 45
    const/4 v7, 0x0

    .line 46
    const/4 v8, 0x0

    .line 47
    invoke-static/range {v2 .. v10}, Ly70/k;->a(Ly70/k;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ly70/w1;I)Ly70/k;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 52
    .line 53
    .line 54
    goto :goto_4

    .line 55
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 56
    .line 57
    if-eqz p2, :cond_5

    .line 58
    .line 59
    iget-object p0, p0, Ly70/o;->q:Lbd0/c;

    .line 60
    .line 61
    check-cast p1, Lne0/e;

    .line 62
    .line 63
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p1, Ljava/lang/String;

    .line 66
    .line 67
    const/16 p2, 0x1e

    .line 68
    .line 69
    and-int/lit8 v0, p2, 0x2

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    const/4 v3, 0x1

    .line 73
    if-eqz v0, :cond_1

    .line 74
    .line 75
    move v6, v3

    .line 76
    goto :goto_0

    .line 77
    :cond_1
    move v6, v2

    .line 78
    :goto_0
    and-int/lit8 v0, p2, 0x4

    .line 79
    .line 80
    if-eqz v0, :cond_2

    .line 81
    .line 82
    move v7, v3

    .line 83
    goto :goto_1

    .line 84
    :cond_2
    move v7, v2

    .line 85
    :goto_1
    and-int/lit8 v0, p2, 0x8

    .line 86
    .line 87
    if-eqz v0, :cond_3

    .line 88
    .line 89
    move v8, v2

    .line 90
    goto :goto_2

    .line 91
    :cond_3
    move v8, v3

    .line 92
    :goto_2
    and-int/lit8 p2, p2, 0x10

    .line 93
    .line 94
    if-eqz p2, :cond_4

    .line 95
    .line 96
    move v9, v2

    .line 97
    goto :goto_3

    .line 98
    :cond_4
    move v9, v3

    .line 99
    :goto_3
    const-string p2, "url"

    .line 100
    .line 101
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 105
    .line 106
    new-instance v5, Ljava/net/URL;

    .line 107
    .line 108
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    move-object v4, p0

    .line 112
    check-cast v4, Lzc0/b;

    .line 113
    .line 114
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 115
    .line 116
    .line 117
    :goto_4
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 118
    .line 119
    return-object v1

    .line 120
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    new-instance p0, La8/r0;

    .line 124
    .line 125
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :pswitch_1
    check-cast p1, Lne0/t;

    .line 130
    .line 131
    invoke-virtual {p0, p1}, Ly70/o;->l(Lne0/t;)V

    .line 132
    .line 133
    .line 134
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 135
    .line 136
    return-object v1

    .line 137
    :pswitch_2
    check-cast p1, Lne0/s;

    .line 138
    .line 139
    invoke-static {p0, p1, p2}, Ly70/o;->k(Ly70/o;Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 144
    .line 145
    if-ne p0, p1, :cond_6

    .line 146
    .line 147
    move-object v1, p0

    .line 148
    :cond_6
    return-object v1

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Ly70/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyy0/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 20
    .line 21
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    :cond_0
    return v1

    .line 30
    :pswitch_0
    instance-of v0, p1, Lyy0/j;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 44
    .line 45
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    :cond_1
    return v1

    .line 54
    :pswitch_1
    instance-of v0, p1, Lyy0/j;

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 60
    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 68
    .line 69
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    :cond_2
    return v1

    .line 78
    :pswitch_2
    instance-of v0, p1, Lyy0/j;

    .line 79
    .line 80
    const/4 v1, 0x0

    .line 81
    if-eqz v0, :cond_3

    .line 82
    .line 83
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 84
    .line 85
    if-eqz v0, :cond_3

    .line 86
    .line 87
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 92
    .line 93
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    :cond_3
    return v1

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Ly70/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :pswitch_1
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :pswitch_2
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    return p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

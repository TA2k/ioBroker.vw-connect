.class public final Lrs0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lrs0/e;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lrs0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lrs0/d;

    .line 7
    .line 8
    iget v1, v0, Lrs0/d;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lrs0/d;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrs0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lrs0/d;-><init>(Lrs0/e;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lrs0/d;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lrs0/d;->h:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lrs0/d;->e:Ljava/util/ArrayList;

    .line 37
    .line 38
    iget-object v0, v0, Lrs0/d;->d:Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    new-instance p0, Ljava/util/ArrayList;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object p0, v0, Lrs0/d;->d:Ljava/util/ArrayList;

    .line 61
    .line 62
    iput-object p0, v0, Lrs0/d;->e:Ljava/util/ArrayList;

    .line 63
    .line 64
    iput v2, v0, Lrs0/d;->h:I

    .line 65
    .line 66
    sget-object v0, Lss0/h;->d:Lss0/h;

    .line 67
    .line 68
    sget-object v1, Lss0/h;->e:Lss0/h;

    .line 69
    .line 70
    sget-object v2, Lss0/h;->f:Lss0/h;

    .line 71
    .line 72
    sget-object v3, Lss0/h;->g:Lss0/h;

    .line 73
    .line 74
    filled-new-array {v0, v1, v2, v3}, [Lss0/h;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-static {v0}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    if-ne v0, p1, :cond_3

    .line 83
    .line 84
    return-object p1

    .line 85
    :cond_3
    move-object p1, p0

    .line 86
    move-object p0, v0

    .line 87
    move-object v0, p1

    .line 88
    :goto_1
    check-cast p0, Ljava/util/List;

    .line 89
    .line 90
    sget-object v1, Lss0/h;->e:Lss0/h;

    .line 91
    .line 92
    invoke-interface {p0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    if-nez v1, :cond_4

    .line 97
    .line 98
    sget-object v1, Lss0/h;->d:Lss0/h;

    .line 99
    .line 100
    invoke-interface {p0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-eqz v1, :cond_5

    .line 105
    .line 106
    :cond_4
    sget-object v1, Lss0/n;->d:Lss0/n;

    .line 107
    .line 108
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    :cond_5
    sget-object v1, Lss0/h;->f:Lss0/h;

    .line 112
    .line 113
    invoke-interface {p0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-eqz v1, :cond_6

    .line 118
    .line 119
    sget-object v1, Lss0/n;->e:Lss0/n;

    .line 120
    .line 121
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    :cond_6
    sget-object v1, Lss0/h;->g:Lss0/h;

    .line 125
    .line 126
    invoke-interface {p0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    if-eqz p0, :cond_7

    .line 131
    .line 132
    sget-object p0, Lss0/n;->f:Lss0/n;

    .line 133
    .line 134
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    :cond_7
    return-object v0
.end method

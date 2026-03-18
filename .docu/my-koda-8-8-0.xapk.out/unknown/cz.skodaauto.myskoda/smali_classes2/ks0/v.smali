.class public final Lks0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfs0/b;

.field public final b:Lbd0/c;


# direct methods
.method public constructor <init>(Lfs0/b;Lbd0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/v;->a:Lfs0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lks0/v;->b:Lbd0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lks0/v;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p2, Lks0/u;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lks0/u;

    .line 7
    .line 8
    iget v1, v0, Lks0/u;->h:I

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
    iput v1, v0, Lks0/u;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lks0/u;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lks0/u;-><init>(Lks0/v;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lks0/u;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lks0/u;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lks0/u;->e:Ld01/z;

    .line 37
    .line 38
    iget-object v0, v0, Lks0/u;->d:Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    new-instance p2, Ld01/z;

    .line 56
    .line 57
    const/4 v2, 0x0

    .line 58
    invoke-direct {p2, v2}, Ld01/z;-><init>(I)V

    .line 59
    .line 60
    .line 61
    const-string v2, "https"

    .line 62
    .line 63
    invoke-virtual {p2, v2}, Ld01/z;->k(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iput-object p1, v0, Lks0/u;->d:Ljava/lang/String;

    .line 67
    .line 68
    iput-object p2, v0, Lks0/u;->e:Ld01/z;

    .line 69
    .line 70
    iput v3, v0, Lks0/u;->h:I

    .line 71
    .line 72
    iget-object v2, p0, Lks0/v;->a:Lfs0/b;

    .line 73
    .line 74
    invoke-virtual {v2, v0}, Lfs0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    if-ne v0, v1, :cond_3

    .line 79
    .line 80
    return-object v1

    .line 81
    :cond_3
    move-object v10, v0

    .line 82
    move-object v0, p1

    .line 83
    move-object p1, p2

    .line 84
    move-object p2, v10

    .line 85
    :goto_1
    check-cast p2, Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {p1, p2}, Ld01/z;->f(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string p2, "transactionId"

    .line 91
    .line 92
    invoke-virtual {p1, p2, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p1}, Ld01/z;->c()Ld01/a0;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    invoke-virtual {p1}, Ld01/a0;->k()Ljava/net/URL;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-virtual {p1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    const-string p2, "toString(...)"

    .line 108
    .line 109
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const/16 p2, 0x10

    .line 113
    .line 114
    and-int/lit8 v0, p2, 0x2

    .line 115
    .line 116
    const/4 v1, 0x0

    .line 117
    if-eqz v0, :cond_4

    .line 118
    .line 119
    move v6, v3

    .line 120
    goto :goto_2

    .line 121
    :cond_4
    move v6, v1

    .line 122
    :goto_2
    and-int/lit8 v0, p2, 0x4

    .line 123
    .line 124
    if-eqz v0, :cond_5

    .line 125
    .line 126
    move v7, v3

    .line 127
    goto :goto_3

    .line 128
    :cond_5
    move v7, v1

    .line 129
    :goto_3
    and-int/lit8 v0, p2, 0x8

    .line 130
    .line 131
    if-eqz v0, :cond_6

    .line 132
    .line 133
    move v8, v1

    .line 134
    goto :goto_4

    .line 135
    :cond_6
    move v8, v3

    .line 136
    :goto_4
    and-int/2addr p2, p2

    .line 137
    if-eqz p2, :cond_7

    .line 138
    .line 139
    move v9, v1

    .line 140
    goto :goto_5

    .line 141
    :cond_7
    move v9, v3

    .line 142
    :goto_5
    iget-object p0, p0, Lks0/v;->b:Lbd0/c;

    .line 143
    .line 144
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 145
    .line 146
    new-instance v5, Ljava/net/URL;

    .line 147
    .line 148
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    move-object v4, p0

    .line 152
    check-cast v4, Lzc0/b;

    .line 153
    .line 154
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0
.end method

.class public final Lbh0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbd0/c;

.field public final b:Lbh0/g;

.field public final c:Lbh0/j;


# direct methods
.method public constructor <init>(Lbd0/c;Lbh0/g;Lbh0/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbh0/i;->a:Lbd0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lbh0/i;->b:Lbh0/g;

    .line 7
    .line 8
    iput-object p3, p0, Lbh0/i;->c:Lbh0/j;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lbh0/i;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p2, Lbh0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lbh0/h;

    .line 7
    .line 8
    iget v1, v0, Lbh0/h;->f:I

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
    iput v1, v0, Lbh0/h;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lbh0/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lbh0/h;-><init>(Lbh0/i;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lbh0/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lbh0/h;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    const/4 v5, 0x2

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v3, :cond_2

    .line 38
    .line 39
    if-ne v2, v5, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v4

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object v4

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const-string p2, "tel:"

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    invoke-static {p1, p2, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    if-eqz v6, :cond_4

    .line 68
    .line 69
    invoke-static {p1, p2}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    iput v3, v0, Lbh0/h;->f:I

    .line 74
    .line 75
    iget-object p0, p0, Lbh0/i;->c:Lbh0/j;

    .line 76
    .line 77
    invoke-virtual {p0, p1, v0}, Lbh0/j;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    if-ne p0, v1, :cond_5

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    const-string p2, "mailto:"

    .line 85
    .line 86
    invoke-static {p1, p2, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 87
    .line 88
    .line 89
    move-result v6

    .line 90
    if-eqz v6, :cond_6

    .line 91
    .line 92
    invoke-static {p1, p2}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    iput v5, v0, Lbh0/h;->f:I

    .line 97
    .line 98
    iget-object p0, p0, Lbh0/i;->b:Lbh0/g;

    .line 99
    .line 100
    invoke-virtual {p0, p1, v0}, Lbh0/g;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-ne p0, v1, :cond_5

    .line 105
    .line 106
    :goto_1
    return-object v1

    .line 107
    :cond_5
    return-object v4

    .line 108
    :cond_6
    const/16 p2, 0x1e

    .line 109
    .line 110
    and-int/lit8 v0, p2, 0x2

    .line 111
    .line 112
    if-eqz v0, :cond_7

    .line 113
    .line 114
    move v7, v3

    .line 115
    goto :goto_2

    .line 116
    :cond_7
    move v7, v2

    .line 117
    :goto_2
    and-int/lit8 v0, p2, 0x4

    .line 118
    .line 119
    if-eqz v0, :cond_8

    .line 120
    .line 121
    move v8, v3

    .line 122
    goto :goto_3

    .line 123
    :cond_8
    move v8, v2

    .line 124
    :goto_3
    and-int/lit8 v0, p2, 0x8

    .line 125
    .line 126
    if-eqz v0, :cond_9

    .line 127
    .line 128
    move v9, v2

    .line 129
    goto :goto_4

    .line 130
    :cond_9
    move v9, v3

    .line 131
    :goto_4
    and-int/lit8 p2, p2, 0x10

    .line 132
    .line 133
    if-eqz p2, :cond_a

    .line 134
    .line 135
    move v10, v2

    .line 136
    goto :goto_5

    .line 137
    :cond_a
    move v10, v3

    .line 138
    :goto_5
    iget-object p0, p0, Lbh0/i;->a:Lbd0/c;

    .line 139
    .line 140
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 141
    .line 142
    new-instance v6, Ljava/net/URL;

    .line 143
    .line 144
    invoke-direct {v6, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    move-object v5, p0

    .line 148
    check-cast v5, Lzc0/b;

    .line 149
    .line 150
    invoke-virtual/range {v5 .. v10}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 151
    .line 152
    .line 153
    return-object v4
.end method

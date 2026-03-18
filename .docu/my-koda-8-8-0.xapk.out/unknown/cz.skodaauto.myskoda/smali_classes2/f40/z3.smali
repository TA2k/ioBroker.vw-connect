.class public final Lf40/z3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/z0;

.field public final b:Lf40/b1;


# direct methods
.method public constructor <init>(Lf40/z0;Lf40/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/z3;->a:Lf40/z0;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/z3;->b:Lf40/b1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lf40/x3;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lf40/z3;->b(Lf40/x3;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lf40/x3;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lf40/y3;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lf40/y3;

    .line 7
    .line 8
    iget v1, v0, Lf40/y3;->f:I

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
    iput v1, v0, Lf40/y3;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lf40/y3;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lf40/y3;-><init>(Lf40/z3;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lf40/y3;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lf40/y3;->f:I

    .line 30
    .line 31
    iget-object v3, p0, Lf40/z3;->a:Lf40/z0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    const/4 v6, 0x0

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v5, :cond_2

    .line 39
    .line 40
    if-ne v2, v4, :cond_1

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_4

    .line 58
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object p1, p1, Lf40/x3;->a:Lf40/w3;

    .line 62
    .line 63
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-eqz p1, :cond_8

    .line 68
    .line 69
    if-ne p1, v5, :cond_7

    .line 70
    .line 71
    iget-object p0, p0, Lf40/z3;->b:Lf40/b1;

    .line 72
    .line 73
    check-cast p0, Ld40/d;

    .line 74
    .line 75
    iget-object p0, p0, Ld40/d;->d:Lyy0/l1;

    .line 76
    .line 77
    iput v4, v0, Lf40/y3;->f:I

    .line 78
    .line 79
    invoke-static {p0, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    if-ne p2, v1, :cond_4

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_4
    :goto_1
    instance-of p0, p2, Lne0/e;

    .line 87
    .line 88
    if-eqz p0, :cond_5

    .line 89
    .line 90
    check-cast p2, Lne0/e;

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_5
    move-object p2, v6

    .line 94
    :goto_2
    if-eqz p2, :cond_6

    .line 95
    .line 96
    iget-object p0, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast p0, Lg40/o0;

    .line 99
    .line 100
    if-eqz p0, :cond_6

    .line 101
    .line 102
    iget-object p0, p0, Lg40/o0;->e:Ljava/util/ArrayList;

    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_6
    move-object p0, v6

    .line 106
    goto :goto_6

    .line 107
    :cond_7
    new-instance p0, La8/r0;

    .line 108
    .line 109
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 110
    .line 111
    .line 112
    throw p0

    .line 113
    :cond_8
    move-object p0, v3

    .line 114
    check-cast p0, Ld40/b;

    .line 115
    .line 116
    iget-object p0, p0, Ld40/b;->e:Lyy0/l1;

    .line 117
    .line 118
    iput v5, v0, Lf40/y3;->f:I

    .line 119
    .line 120
    invoke-static {p0, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p2

    .line 124
    if-ne p2, v1, :cond_9

    .line 125
    .line 126
    :goto_3
    return-object v1

    .line 127
    :cond_9
    :goto_4
    instance-of p0, p2, Lne0/e;

    .line 128
    .line 129
    if-eqz p0, :cond_a

    .line 130
    .line 131
    check-cast p2, Lne0/e;

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_a
    move-object p2, v6

    .line 135
    :goto_5
    if-eqz p2, :cond_6

    .line 136
    .line 137
    iget-object p0, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast p0, Lg40/t;

    .line 140
    .line 141
    if-eqz p0, :cond_6

    .line 142
    .line 143
    iget-object p0, p0, Lg40/t;->c:Ljava/util/ArrayList;

    .line 144
    .line 145
    :goto_6
    if-eqz p0, :cond_d

    .line 146
    .line 147
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    :cond_b
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 152
    .line 153
    .line 154
    move-result p1

    .line 155
    if-eqz p1, :cond_c

    .line 156
    .line 157
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    move-object p2, p1

    .line 162
    check-cast p2, Lg40/p;

    .line 163
    .line 164
    iget-object v0, p2, Lg40/p;->c:Lg40/r;

    .line 165
    .line 166
    sget-object v1, Lg40/r;->f:Lg40/r;

    .line 167
    .line 168
    if-ne v0, v1, :cond_b

    .line 169
    .line 170
    iget-object p2, p2, Lg40/p;->b:Lg40/s;

    .line 171
    .line 172
    sget-object v0, Lg40/s;->i:Lg40/s;

    .line 173
    .line 174
    if-ne p2, v0, :cond_b

    .line 175
    .line 176
    move-object v6, p1

    .line 177
    :cond_c
    check-cast v6, Lg40/p;

    .line 178
    .line 179
    :cond_d
    check-cast v3, Ld40/b;

    .line 180
    .line 181
    iput-object v6, v3, Ld40/b;->g:Lg40/p;

    .line 182
    .line 183
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 184
    .line 185
    return-object p0
.end method

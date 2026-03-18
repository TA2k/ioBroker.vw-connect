.class public final Lf40/m3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/d1;

.field public final b:Lf40/b1;


# direct methods
.method public constructor <init>(Lf40/d1;Lf40/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/m3;->a:Lf40/d1;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/m3;->b:Lf40/b1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lf40/j3;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lf40/m3;->b(Lf40/j3;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lf40/j3;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lf40/l3;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lf40/l3;

    .line 7
    .line 8
    iget v1, v0, Lf40/l3;->g:I

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
    iput v1, v0, Lf40/l3;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lf40/l3;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lf40/l3;-><init>(Lf40/m3;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lf40/l3;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lf40/l3;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lf40/m3;->a:Lf40/d1;

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
    iget-object p1, v0, Lf40/l3;->d:Lf40/j3;

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-object p1, v0, Lf40/l3;->d:Lf40/j3;

    .line 57
    .line 58
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_4

    .line 62
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p2, p1, Lf40/j3;->b:Lf40/k3;

    .line 66
    .line 67
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    if-eqz p2, :cond_8

    .line 72
    .line 73
    if-ne p2, v5, :cond_7

    .line 74
    .line 75
    iget-object p0, p0, Lf40/m3;->b:Lf40/b1;

    .line 76
    .line 77
    check-cast p0, Ld40/d;

    .line 78
    .line 79
    iget-object p0, p0, Ld40/d;->d:Lyy0/l1;

    .line 80
    .line 81
    iput-object p1, v0, Lf40/l3;->d:Lf40/j3;

    .line 82
    .line 83
    iput v4, v0, Lf40/l3;->g:I

    .line 84
    .line 85
    invoke-static {p0, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    if-ne p2, v1, :cond_4

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_4
    :goto_1
    instance-of p0, p2, Lne0/e;

    .line 93
    .line 94
    if-eqz p0, :cond_5

    .line 95
    .line 96
    check-cast p2, Lne0/e;

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_5
    move-object p2, v6

    .line 100
    :goto_2
    if-eqz p2, :cond_6

    .line 101
    .line 102
    iget-object p0, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p0, Lg40/o0;

    .line 105
    .line 106
    if-eqz p0, :cond_6

    .line 107
    .line 108
    iget-object p0, p0, Lg40/o0;->f:Ljava/util/ArrayList;

    .line 109
    .line 110
    goto :goto_6

    .line 111
    :cond_6
    move-object p0, v6

    .line 112
    goto :goto_6

    .line 113
    :cond_7
    new-instance p0, La8/r0;

    .line 114
    .line 115
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 116
    .line 117
    .line 118
    throw p0

    .line 119
    :cond_8
    move-object p0, v3

    .line 120
    check-cast p0, Ld40/f;

    .line 121
    .line 122
    iget-object p0, p0, Ld40/f;->d:Lyy0/l1;

    .line 123
    .line 124
    iput-object p1, v0, Lf40/l3;->d:Lf40/j3;

    .line 125
    .line 126
    iput v5, v0, Lf40/l3;->g:I

    .line 127
    .line 128
    invoke-static {p0, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p2

    .line 132
    if-ne p2, v1, :cond_9

    .line 133
    .line 134
    :goto_3
    return-object v1

    .line 135
    :cond_9
    :goto_4
    instance-of p0, p2, Lne0/e;

    .line 136
    .line 137
    if-eqz p0, :cond_a

    .line 138
    .line 139
    check-cast p2, Lne0/e;

    .line 140
    .line 141
    goto :goto_5

    .line 142
    :cond_a
    move-object p2, v6

    .line 143
    :goto_5
    if-eqz p2, :cond_6

    .line 144
    .line 145
    iget-object p0, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast p0, Lg40/t0;

    .line 148
    .line 149
    if-eqz p0, :cond_6

    .line 150
    .line 151
    iget-object p0, p0, Lg40/t0;->c:Ljava/util/ArrayList;

    .line 152
    .line 153
    :goto_6
    if-eqz p0, :cond_d

    .line 154
    .line 155
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    :cond_b
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 160
    .line 161
    .line 162
    move-result p2

    .line 163
    if-eqz p2, :cond_c

    .line 164
    .line 165
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p2

    .line 169
    move-object v0, p2

    .line 170
    check-cast v0, Lg40/a;

    .line 171
    .line 172
    iget-object v0, v0, Lg40/a;->a:Ljava/lang/String;

    .line 173
    .line 174
    iget-object v1, p1, Lf40/j3;->a:Ljava/lang/String;

    .line 175
    .line 176
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    if-eqz v0, :cond_b

    .line 181
    .line 182
    move-object v6, p2

    .line 183
    :cond_c
    check-cast v6, Lg40/a;

    .line 184
    .line 185
    :cond_d
    check-cast v3, Ld40/f;

    .line 186
    .line 187
    iput-object v6, v3, Ld40/f;->f:Lg40/a;

    .line 188
    .line 189
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    return-object p0
.end method

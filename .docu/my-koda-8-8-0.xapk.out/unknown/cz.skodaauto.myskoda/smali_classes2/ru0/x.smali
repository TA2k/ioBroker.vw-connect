.class public final Lru0/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lru0/m;

.field public final b:Lqd0/o0;

.field public final c:Lpu0/b;

.field public final d:Lqd0/x;


# direct methods
.method public constructor <init>(Lru0/m;Lqd0/o0;Lpu0/b;Lqd0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru0/x;->a:Lru0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lru0/x;->b:Lqd0/o0;

    .line 7
    .line 8
    iput-object p3, p0, Lru0/x;->c:Lpu0/b;

    .line 9
    .line 10
    iput-object p4, p0, Lru0/x;->d:Lqd0/x;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lru0/x;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lru0/v;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lru0/v;

    .line 7
    .line 8
    iget v1, v0, Lru0/v;->h:I

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
    iput v1, v0, Lru0/v;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lru0/v;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lru0/v;-><init>(Lru0/x;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lru0/v;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lru0/v;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    iget-object v1, v0, Lru0/v;->e:Lyy0/i;

    .line 41
    .line 42
    check-cast v1, Lyy0/i;

    .line 43
    .line 44
    iget-object v0, v0, Lru0/v;->d:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iput v4, v0, Lru0/v;->h:I

    .line 66
    .line 67
    iget-object p1, p0, Lru0/x;->a:Lru0/m;

    .line 68
    .line 69
    iget-object v2, p1, Lru0/m;->a:Lkf0/z;

    .line 70
    .line 71
    invoke-virtual {v2}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    check-cast v2, Lyy0/i;

    .line 76
    .line 77
    new-instance v6, Lhg/q;

    .line 78
    .line 79
    const/16 v7, 0x1c

    .line 80
    .line 81
    invoke-direct {v6, v2, v7}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 82
    .line 83
    .line 84
    new-instance v2, Llb0/y;

    .line 85
    .line 86
    const/16 v7, 0x9

    .line 87
    .line 88
    invoke-direct {v2, v7, v6, p1}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    new-instance v6, Lru0/j;

    .line 92
    .line 93
    invoke-direct {v6, v5, p1}, Lru0/j;-><init>(Lkotlin/coroutines/Continuation;Lru0/m;)V

    .line 94
    .line 95
    .line 96
    invoke-static {v2, v6}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    if-ne p1, v1, :cond_4

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_4
    :goto_1
    check-cast p1, Lyy0/i;

    .line 104
    .line 105
    iget-object v2, p0, Lru0/x;->b:Lqd0/o0;

    .line 106
    .line 107
    invoke-virtual {v2}, Lqd0/o0;->invoke()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    iput-object v2, v0, Lru0/v;->d:Ljava/lang/Object;

    .line 112
    .line 113
    move-object v6, p1

    .line 114
    check-cast v6, Lyy0/i;

    .line 115
    .line 116
    iput-object v6, v0, Lru0/v;->e:Lyy0/i;

    .line 117
    .line 118
    iput v3, v0, Lru0/v;->h:I

    .line 119
    .line 120
    iget-object v6, p0, Lru0/x;->d:Lqd0/x;

    .line 121
    .line 122
    invoke-virtual {v6, v0}, Lqd0/x;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    if-ne v0, v1, :cond_5

    .line 127
    .line 128
    :goto_2
    return-object v1

    .line 129
    :cond_5
    move-object v1, p1

    .line 130
    move-object p1, v0

    .line 131
    move-object v0, v2

    .line 132
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 133
    .line 134
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    if-eqz p1, :cond_6

    .line 139
    .line 140
    goto :goto_4

    .line 141
    :cond_6
    move-object v0, v5

    .line 142
    :goto_4
    check-cast v0, Lyy0/i;

    .line 143
    .line 144
    const/4 p1, 0x0

    .line 145
    if-nez v0, :cond_7

    .line 146
    .line 147
    new-instance v0, Lne0/e;

    .line 148
    .line 149
    invoke-direct {v0, v5}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    new-instance v2, Lyy0/m;

    .line 153
    .line 154
    invoke-direct {v2, v0, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 155
    .line 156
    .line 157
    move-object v0, v2

    .line 158
    :cond_7
    iget-object p0, p0, Lru0/x;->c:Lpu0/b;

    .line 159
    .line 160
    iget-object p0, p0, Lpu0/b;->b:Lyy0/c2;

    .line 161
    .line 162
    new-instance v2, Lru0/w;

    .line 163
    .line 164
    const/4 v6, 0x5

    .line 165
    invoke-direct {v2, v6, v5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 166
    .line 167
    .line 168
    const/4 v6, 0x3

    .line 169
    new-array v6, v6, [Lyy0/i;

    .line 170
    .line 171
    aput-object v1, v6, p1

    .line 172
    .line 173
    aput-object v0, v6, v4

    .line 174
    .line 175
    aput-object p0, v6, v3

    .line 176
    .line 177
    new-instance p0, Lws/b;

    .line 178
    .line 179
    invoke-direct {p0, v6, v5, v2}, Lws/b;-><init>([Lyy0/i;Lkotlin/coroutines/Continuation;Lay0/q;)V

    .line 180
    .line 181
    .line 182
    new-instance p1, Lyy0/m1;

    .line 183
    .line 184
    invoke-direct {p1, p0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 185
    .line 186
    .line 187
    return-object p1
.end method

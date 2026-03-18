.class public final Lu30/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lzd0/c;

.field public final b:Lgb0/l;

.field public final c:Lcs0/p;

.field public final d:Lcs0/c;

.field public final e:Lu30/t;


# direct methods
.method public constructor <init>(Lzd0/c;Lgb0/l;Lcs0/p;Lcs0/c;Lu30/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu30/e0;->a:Lzd0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lu30/e0;->b:Lgb0/l;

    .line 7
    .line 8
    iput-object p3, p0, Lu30/e0;->c:Lcs0/p;

    .line 9
    .line 10
    iput-object p4, p0, Lu30/e0;->d:Lcs0/c;

    .line 11
    .line 12
    iput-object p5, p0, Lu30/e0;->e:Lu30/t;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lu30/e0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lu30/e0;->a:Lzd0/c;

    .line 2
    .line 3
    iget-object v0, v0, Lzd0/c;->a:Lxd0/b;

    .line 4
    .line 5
    instance-of v1, p1, Lu30/d0;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lu30/d0;

    .line 11
    .line 12
    iget v2, v1, Lu30/d0;->f:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lu30/d0;->f:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lu30/d0;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lu30/d0;-><init>(Lu30/e0;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, v1, Lu30/d0;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lu30/d0;->f:I

    .line 34
    .line 35
    const/4 v4, 0x5

    .line 36
    const/4 v5, 0x4

    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    if-eqz v3, :cond_6

    .line 41
    .line 42
    if-eq v3, v8, :cond_5

    .line 43
    .line 44
    if-eq v3, v7, :cond_4

    .line 45
    .line 46
    if-eq v3, v6, :cond_3

    .line 47
    .line 48
    if-eq v3, v5, :cond_2

    .line 49
    .line 50
    if-ne v3, v4, :cond_1

    .line 51
    .line 52
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_6

    .line 56
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 59
    .line 60
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_4

    .line 68
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iput v8, v1, Lu30/d0;->f:I

    .line 84
    .line 85
    sget-object p1, Lyi0/e;->a:Lyi0/e;

    .line 86
    .line 87
    invoke-virtual {v0, p1, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    if-ne p1, v2, :cond_7

    .line 92
    .line 93
    goto :goto_5

    .line 94
    :cond_7
    :goto_1
    check-cast p1, Lne0/t;

    .line 95
    .line 96
    instance-of v3, p1, Lne0/c;

    .line 97
    .line 98
    if-eqz v3, :cond_8

    .line 99
    .line 100
    check-cast p1, Lne0/c;

    .line 101
    .line 102
    return-object p1

    .line 103
    :cond_8
    iput v7, v1, Lu30/d0;->f:I

    .line 104
    .line 105
    sget-object p1, Lyi0/b;->a:Lyi0/b;

    .line 106
    .line 107
    invoke-virtual {v0, p1, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    if-ne p1, v2, :cond_9

    .line 112
    .line 113
    goto :goto_5

    .line 114
    :cond_9
    :goto_2
    iput v6, v1, Lu30/d0;->f:I

    .line 115
    .line 116
    iget-object p1, p0, Lu30/e0;->c:Lcs0/p;

    .line 117
    .line 118
    invoke-virtual {p1, v1}, Lcs0/p;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    if-ne p1, v2, :cond_a

    .line 123
    .line 124
    goto :goto_5

    .line 125
    :cond_a
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 126
    .line 127
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 128
    .line 129
    .line 130
    move-result p1

    .line 131
    if-eqz p1, :cond_b

    .line 132
    .line 133
    iput v5, v1, Lu30/d0;->f:I

    .line 134
    .line 135
    iget-object p1, p0, Lu30/e0;->d:Lcs0/c;

    .line 136
    .line 137
    invoke-virtual {p1, v1}, Lcs0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    if-ne p1, v2, :cond_b

    .line 142
    .line 143
    goto :goto_5

    .line 144
    :cond_b
    :goto_4
    iput v4, v1, Lu30/d0;->f:I

    .line 145
    .line 146
    iget-object p1, p0, Lu30/e0;->b:Lgb0/l;

    .line 147
    .line 148
    invoke-virtual {p1, v1}, Lgb0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    if-ne p1, v2, :cond_c

    .line 153
    .line 154
    :goto_5
    return-object v2

    .line 155
    :cond_c
    :goto_6
    iget-object p0, p0, Lu30/e0;->e:Lu30/t;

    .line 156
    .line 157
    invoke-virtual {p0}, Lu30/t;->invoke()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    new-instance p0, Lne0/e;

    .line 161
    .line 162
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    return-object p0
.end method

.class public final Lz30/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lzd0/c;

.field public final b:Lz30/d;

.field public final c:Lkc0/q;

.field public final d:Lz30/b;

.field public final e:Lee0/f;


# direct methods
.method public constructor <init>(Lzd0/c;Lz30/d;Lkc0/q;Lz30/b;Lee0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz30/h;->a:Lzd0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lz30/h;->b:Lz30/d;

    .line 7
    .line 8
    iput-object p3, p0, Lz30/h;->c:Lkc0/q;

    .line 9
    .line 10
    iput-object p4, p0, Lz30/h;->d:Lz30/b;

    .line 11
    .line 12
    iput-object p5, p0, Lz30/h;->e:Lee0/f;

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
    invoke-virtual {p0, p2}, Lz30/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lz30/h;->a:Lzd0/c;

    .line 2
    .line 3
    iget-object v0, v0, Lzd0/c;->a:Lxd0/b;

    .line 4
    .line 5
    instance-of v1, p1, Lz30/g;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lz30/g;

    .line 11
    .line 12
    iget v2, v1, Lz30/g;->f:I

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
    iput v2, v1, Lz30/g;->f:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lz30/g;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lz30/g;-><init>(Lz30/h;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, v1, Lz30/g;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lz30/g;->f:I

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
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    if-eqz v3, :cond_6

    .line 43
    .line 44
    if-eq v3, v8, :cond_5

    .line 45
    .line 46
    if-eq v3, v7, :cond_4

    .line 47
    .line 48
    if-eq v3, v6, :cond_3

    .line 49
    .line 50
    if-eq v3, v5, :cond_2

    .line 51
    .line 52
    if-ne v3, v4, :cond_1

    .line 53
    .line 54
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_6

    .line 58
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iput v8, v1, Lz30/g;->f:I

    .line 86
    .line 87
    iget-object p1, p0, Lz30/h;->c:Lkc0/q;

    .line 88
    .line 89
    invoke-virtual {p1, v9, v1}, Lkc0/q;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    if-ne p1, v2, :cond_7

    .line 94
    .line 95
    goto :goto_5

    .line 96
    :cond_7
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 97
    .line 98
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    if-nez p1, :cond_b

    .line 103
    .line 104
    iput v7, v1, Lz30/g;->f:I

    .line 105
    .line 106
    sget-object p1, La40/a;->a:La40/a;

    .line 107
    .line 108
    invoke-virtual {v0, p1, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-ne p1, v2, :cond_8

    .line 113
    .line 114
    goto :goto_5

    .line 115
    :cond_8
    :goto_2
    iput v6, v1, Lz30/g;->f:I

    .line 116
    .line 117
    sget-object p1, Llc0/h;->a:Llc0/h;

    .line 118
    .line 119
    invoke-virtual {v0, p1, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    if-ne p1, v2, :cond_9

    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_9
    :goto_3
    check-cast p1, Lne0/t;

    .line 127
    .line 128
    instance-of v0, p1, Lne0/c;

    .line 129
    .line 130
    if-eqz v0, :cond_a

    .line 131
    .line 132
    check-cast p1, Lne0/c;

    .line 133
    .line 134
    return-object p1

    .line 135
    :cond_a
    iput v5, v1, Lz30/g;->f:I

    .line 136
    .line 137
    iget-object p1, p0, Lz30/h;->e:Lee0/f;

    .line 138
    .line 139
    invoke-virtual {p1, v1}, Lee0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    if-ne p1, v2, :cond_b

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_b
    :goto_4
    iput v4, v1, Lz30/g;->f:I

    .line 147
    .line 148
    iget-object p1, p0, Lz30/h;->d:Lz30/b;

    .line 149
    .line 150
    invoke-virtual {p1, v1}, Lz30/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    if-ne p1, v2, :cond_c

    .line 155
    .line 156
    :goto_5
    return-object v2

    .line 157
    :cond_c
    :goto_6
    new-instance p1, Lxf/b;

    .line 158
    .line 159
    const/16 v0, 0x1d

    .line 160
    .line 161
    invoke-direct {p1, v0}, Lxf/b;-><init>(I)V

    .line 162
    .line 163
    .line 164
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 165
    .line 166
    .line 167
    iget-object p0, p0, Lz30/h;->b:Lz30/d;

    .line 168
    .line 169
    invoke-virtual {p0}, Lz30/d;->invoke()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    new-instance p0, Lne0/e;

    .line 173
    .line 174
    invoke-direct {p0, v9}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    return-object p0
.end method

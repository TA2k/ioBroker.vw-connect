.class public final Lee0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkc0/f0;

.field public final b:Lkc0/t0;

.field public final c:Lee0/a;


# direct methods
.method public constructor <init>(Lkc0/f0;Lkc0/t0;Lee0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lee0/d;->a:Lkc0/f0;

    .line 5
    .line 6
    iput-object p2, p0, Lee0/d;->b:Lkc0/t0;

    .line 7
    .line 8
    iput-object p3, p0, Lee0/d;->c:Lee0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lee0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lee0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lee0/c;

    .line 7
    .line 8
    iget v1, v0, Lee0/c;->g:I

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
    iput v1, v0, Lee0/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lee0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lee0/c;-><init>(Lee0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lee0/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lee0/c;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lee0/d;->c:Lee0/a;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    const/4 v6, 0x4

    .line 37
    const/4 v7, 0x3

    .line 38
    const/4 v8, 0x2

    .line 39
    const/4 v9, 0x1

    .line 40
    if-eqz v2, :cond_5

    .line 41
    .line 42
    if-eq v2, v9, :cond_4

    .line 43
    .line 44
    if-eq v2, v8, :cond_3

    .line 45
    .line 46
    if-eq v2, v7, :cond_2

    .line 47
    .line 48
    if-ne v2, v6, :cond_1

    .line 49
    .line 50
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object v5

    .line 54
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_2
    iget p0, v0, Lee0/c;->d:I

    .line 63
    .line 64
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    return-object v5

    .line 72
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iput v9, v0, Lee0/c;->g:I

    .line 80
    .line 81
    iget-object p1, p0, Lee0/d;->a:Lkc0/f0;

    .line 82
    .line 83
    invoke-virtual {p1, v0}, Lkc0/f0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    if-ne p1, v1, :cond_6

    .line 88
    .line 89
    goto :goto_5

    .line 90
    :cond_6
    :goto_1
    check-cast p1, Lne0/t;

    .line 91
    .line 92
    instance-of v2, p1, Lne0/c;

    .line 93
    .line 94
    if-eqz v2, :cond_7

    .line 95
    .line 96
    move-object v2, p1

    .line 97
    check-cast v2, Lne0/c;

    .line 98
    .line 99
    iget-object v2, v2, Lne0/c;->a:Ljava/lang/Throwable;

    .line 100
    .line 101
    instance-of v2, v2, Lcd0/a;

    .line 102
    .line 103
    if-eqz v2, :cond_7

    .line 104
    .line 105
    iput v4, v0, Lee0/c;->d:I

    .line 106
    .line 107
    iput v8, v0, Lee0/c;->g:I

    .line 108
    .line 109
    iget-object p0, p0, Lee0/d;->b:Lkc0/t0;

    .line 110
    .line 111
    invoke-virtual {p0, v0}, Lkc0/t0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    if-ne p0, v1, :cond_b

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_7
    instance-of p0, p1, Lne0/e;

    .line 119
    .line 120
    if-eqz p0, :cond_b

    .line 121
    .line 122
    iput v4, v0, Lee0/c;->d:I

    .line 123
    .line 124
    iput v7, v0, Lee0/c;->g:I

    .line 125
    .line 126
    move-object p0, v3

    .line 127
    check-cast p0, Lce0/b;

    .line 128
    .line 129
    iget-object p0, p0, Lce0/b;->a:Lve0/u;

    .line 130
    .line 131
    const-string p1, "marketing_reconsent_completed_app_version"

    .line 132
    .line 133
    const-string v2, "8.8.0"

    .line 134
    .line 135
    invoke-virtual {p0, p1, v2, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    if-ne p0, v1, :cond_8

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_8
    move-object p0, v5

    .line 143
    :goto_2
    if-ne p0, v1, :cond_9

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_9
    move p0, v4

    .line 147
    :goto_3
    iput p0, v0, Lee0/c;->d:I

    .line 148
    .line 149
    iput v6, v0, Lee0/c;->g:I

    .line 150
    .line 151
    check-cast v3, Lce0/b;

    .line 152
    .line 153
    iget-object p0, v3, Lce0/b;->a:Lve0/u;

    .line 154
    .line 155
    const-string p1, "marketing_reconsent_required"

    .line 156
    .line 157
    invoke-virtual {p0, v4, p1, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    if-ne p0, v1, :cond_a

    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_a
    move-object p0, v5

    .line 165
    :goto_4
    if-ne p0, v1, :cond_b

    .line 166
    .line 167
    :goto_5
    return-object v1

    .line 168
    :cond_b
    return-object v5
.end method

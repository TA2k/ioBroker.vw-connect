.class public final Lp1/t;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lp1/v;

.field public final synthetic g:I

.field public final synthetic h:F

.field public final synthetic i:Lc1/j;


# direct methods
.method public constructor <init>(Lp1/v;IFLc1/j;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lp1/t;->f:Lp1/v;

    .line 2
    .line 3
    iput p2, p0, Lp1/t;->g:I

    .line 4
    .line 5
    iput p3, p0, Lp1/t;->h:F

    .line 6
    .line 7
    iput-object p4, p0, Lp1/t;->i:Lc1/j;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lp1/t;

    .line 2
    .line 3
    iget v3, p0, Lp1/t;->h:F

    .line 4
    .line 5
    iget-object v4, p0, Lp1/t;->i:Lc1/j;

    .line 6
    .line 7
    iget-object v1, p0, Lp1/t;->f:Lp1/v;

    .line 8
    .line 9
    iget v2, p0, Lp1/t;->g:I

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Lp1/t;-><init>(Lp1/v;IFLc1/j;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Lp1/t;->e:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lg1/e2;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lp1/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lp1/t;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lp1/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lp1/t;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    if-ne v1, v3, :cond_0

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-object v2

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p0, Lp1/t;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Lg1/e2;

    .line 30
    .line 31
    new-instance v1, Lm1/p;

    .line 32
    .line 33
    iget-object v4, p0, Lp1/t;->f:Lp1/v;

    .line 34
    .line 35
    invoke-direct {v1, p1, v4, v3}, Lm1/p;-><init>(Lg1/e2;Lg1/q2;I)V

    .line 36
    .line 37
    .line 38
    iput v3, p0, Lp1/t;->d:I

    .line 39
    .line 40
    sget p1, Lp1/y;->a:F

    .line 41
    .line 42
    new-instance p1, Ljava/lang/Integer;

    .line 43
    .line 44
    iget v5, p0, Lp1/t;->g:I

    .line 45
    .line 46
    invoke-direct {p1, v5}, Ljava/lang/Integer;-><init>(I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    invoke-virtual {v4, p1}, Lp1/v;->j(I)I

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    iget-object v6, v4, Lp1/v;->s:Ll2/g1;

    .line 58
    .line 59
    invoke-virtual {v6, p1}, Ll2/g1;->p(I)V

    .line 60
    .line 61
    .line 62
    iget p1, v4, Lp1/v;->e:I

    .line 63
    .line 64
    const/4 v6, 0x0

    .line 65
    if-le v5, p1, :cond_2

    .line 66
    .line 67
    move p1, v3

    .line 68
    goto :goto_0

    .line 69
    :cond_2
    move p1, v6

    .line 70
    :goto_0
    invoke-virtual {v1}, Lm1/p;->e()I

    .line 71
    .line 72
    .line 73
    move-result v7

    .line 74
    iget v8, v4, Lp1/v;->e:I

    .line 75
    .line 76
    sub-int/2addr v7, v8

    .line 77
    add-int/2addr v7, v3

    .line 78
    if-eqz p1, :cond_3

    .line 79
    .line 80
    invoke-virtual {v1}, Lm1/p;->e()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-gt v5, v3, :cond_4

    .line 85
    .line 86
    :cond_3
    if-nez p1, :cond_8

    .line 87
    .line 88
    iget v3, v4, Lp1/v;->e:I

    .line 89
    .line 90
    if-ge v5, v3, :cond_8

    .line 91
    .line 92
    :cond_4
    iget v3, v4, Lp1/v;->e:I

    .line 93
    .line 94
    sub-int v3, v5, v3

    .line 95
    .line 96
    invoke-static {v3}, Ljava/lang/Math;->abs(I)I

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    const/4 v8, 0x3

    .line 101
    if-lt v3, v8, :cond_8

    .line 102
    .line 103
    if-eqz p1, :cond_5

    .line 104
    .line 105
    sub-int p1, v5, v7

    .line 106
    .line 107
    iget v3, v4, Lp1/v;->e:I

    .line 108
    .line 109
    if-ge p1, v3, :cond_7

    .line 110
    .line 111
    move p1, v3

    .line 112
    goto :goto_1

    .line 113
    :cond_5
    add-int/2addr v7, v5

    .line 114
    iget p1, v4, Lp1/v;->e:I

    .line 115
    .line 116
    if-le v7, p1, :cond_6

    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_6
    move p1, v7

    .line 120
    :cond_7
    :goto_1
    invoke-virtual {v1, p1, v6}, Lm1/p;->f(II)V

    .line 121
    .line 122
    .line 123
    :cond_8
    invoke-virtual {v1, v5}, Lm1/p;->b(I)I

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    int-to-float p1, p1

    .line 128
    iget v3, p0, Lp1/t;->h:F

    .line 129
    .line 130
    add-float v5, p1, v3

    .line 131
    .line 132
    new-instance p1, Lkotlin/jvm/internal/c0;

    .line 133
    .line 134
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 135
    .line 136
    .line 137
    new-instance v7, Lo50/b;

    .line 138
    .line 139
    const/4 v3, 0x5

    .line 140
    invoke-direct {v7, v3, p1, v1}, Lo50/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    const/4 v9, 0x4

    .line 144
    const/4 v4, 0x0

    .line 145
    iget-object v6, p0, Lp1/t;->i:Lc1/j;

    .line 146
    .line 147
    move-object v8, p0

    .line 148
    invoke-static/range {v4 .. v9}, Lc1/d;->e(FFLc1/j;Lay0/n;Lrx0/i;I)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-ne p0, v0, :cond_9

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_9
    move-object p0, v2

    .line 156
    :goto_2
    if-ne p0, v0, :cond_a

    .line 157
    .line 158
    return-object v0

    .line 159
    :cond_a
    return-object v2
.end method

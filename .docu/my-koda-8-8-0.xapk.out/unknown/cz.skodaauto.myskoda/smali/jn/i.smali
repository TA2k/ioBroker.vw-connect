.class public final Ljn/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public final synthetic e:Lc1/c;

.field public final synthetic f:F

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:F

.field public final synthetic j:Lay0/k;


# direct methods
.method public constructor <init>(Lc1/c;FLjava/util/List;Ljava/lang/Integer;FLay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ljn/i;->e:Lc1/c;

    .line 2
    .line 3
    iput p2, p0, Ljn/i;->f:F

    .line 4
    .line 5
    iput-object p3, p0, Ljn/i;->g:Ljava/util/List;

    .line 6
    .line 7
    iput-object p4, p0, Ljn/i;->h:Ljava/lang/Integer;

    .line 8
    .line 9
    iput p5, p0, Ljn/i;->i:F

    .line 10
    .line 11
    iput-object p6, p0, Ljn/i;->j:Lay0/k;

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    new-instance v0, Ljn/i;

    .line 2
    .line 3
    iget v5, p0, Ljn/i;->i:F

    .line 4
    .line 5
    iget-object v6, p0, Ljn/i;->j:Lay0/k;

    .line 6
    .line 7
    iget-object v1, p0, Ljn/i;->e:Lc1/c;

    .line 8
    .line 9
    iget v2, p0, Ljn/i;->f:F

    .line 10
    .line 11
    iget-object v3, p0, Ljn/i;->g:Ljava/util/List;

    .line 12
    .line 13
    iget-object v4, p0, Ljn/i;->h:Ljava/lang/Integer;

    .line 14
    .line 15
    move-object v7, p2

    .line 16
    invoke-direct/range {v0 .. v7}, Ljn/i;-><init>(Lc1/c;FLjava/util/List;Ljava/lang/Integer;FLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ljn/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljn/i;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljn/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ljn/i;->d:I

    .line 4
    .line 5
    iget v2, p0, Ljn/i;->i:F

    .line 6
    .line 7
    iget-object v3, p0, Ljn/i;->e:Lc1/c;

    .line 8
    .line 9
    const/4 v10, 0x1

    .line 10
    const/4 v11, 0x2

    .line 11
    if-eqz v1, :cond_2

    .line 12
    .line 13
    if-eq v1, v10, :cond_1

    .line 14
    .line 15
    if-ne v1, v11, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto/16 :goto_2

    .line 21
    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    move-object v8, p0

    .line 34
    goto :goto_0

    .line 35
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-static {v11}, Lc1/d;->o(I)Lc1/u;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance v1, Ljn/h;

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    invoke-direct {v1, v4, v2}, Ljn/h;-><init>(IF)V

    .line 46
    .line 47
    .line 48
    iput v10, p0, Ljn/i;->d:I

    .line 49
    .line 50
    invoke-virtual {v3}, Lc1/c;->d()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    check-cast v4, Ljava/lang/Number;

    .line 55
    .line 56
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    iget v5, p0, Ljn/i;->f:F

    .line 61
    .line 62
    invoke-static {p1, v4, v5}, Lc1/d;->k(Lc1/u;FF)F

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    new-instance v4, Ljava/lang/Float;

    .line 67
    .line 68
    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, v4}, Ljn/h;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    move-object v4, p1

    .line 76
    check-cast v4, Ljava/lang/Float;

    .line 77
    .line 78
    new-instance v6, Ljava/lang/Float;

    .line 79
    .line 80
    invoke-direct {v6, v5}, Ljava/lang/Float;-><init>(F)V

    .line 81
    .line 82
    .line 83
    const/4 v9, 0x2

    .line 84
    const/4 v5, 0x0

    .line 85
    const/4 v7, 0x0

    .line 86
    move-object v8, p0

    .line 87
    invoke-static/range {v3 .. v9}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    if-ne p1, v0, :cond_3

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_3
    :goto_0
    check-cast p1, Lc1/h;

    .line 95
    .line 96
    iget-object p0, p1, Lc1/h;->a:Lc1/k;

    .line 97
    .line 98
    iget-object p0, p0, Lc1/k;->e:Ll2/j1;

    .line 99
    .line 100
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    check-cast p0, Ljava/lang/Number;

    .line 105
    .line 106
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    iget-object p1, v8, Ljn/i;->h:Ljava/lang/Integer;

    .line 111
    .line 112
    iget-object v1, v8, Ljn/i;->g:Ljava/util/List;

    .line 113
    .line 114
    invoke-interface {v1, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    div-float/2addr p0, v2

    .line 119
    float-to-int p0, p0

    .line 120
    sub-int/2addr p1, p0

    .line 121
    move-object p0, v1

    .line 122
    check-cast p0, Ljava/util/Collection;

    .line 123
    .line 124
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    sub-int/2addr p0, v10

    .line 129
    invoke-static {p1, p0}, Ljava/lang/Math;->min(II)I

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    const/4 p1, 0x0

    .line 134
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    invoke-interface {v1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    iget-object p1, v8, Ljn/i;->j:Lay0/k;

    .line 143
    .line 144
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    new-instance p0, Ljava/lang/Float;

    .line 148
    .line 149
    const/4 p1, 0x0

    .line 150
    invoke-direct {p0, p1}, Ljava/lang/Float;-><init>(F)V

    .line 151
    .line 152
    .line 153
    iput v11, v8, Ljn/i;->d:I

    .line 154
    .line 155
    invoke-virtual {v3, p0, v8}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, v0, :cond_4

    .line 160
    .line 161
    :goto_1
    return-object v0

    .line 162
    :cond_4
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    return-object p0
.end method

.class public final Lf71/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public final synthetic e:Lc1/c;

.field public final synthetic f:J

.field public final synthetic g:Z

.field public final synthetic h:Ll2/b1;


# direct methods
.method public constructor <init>(Lc1/c;JZLl2/b1;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lf71/e;->e:Lc1/c;

    .line 2
    .line 3
    iput-wide p2, p0, Lf71/e;->f:J

    .line 4
    .line 5
    iput-boolean p4, p0, Lf71/e;->g:Z

    .line 6
    .line 7
    iput-object p5, p0, Lf71/e;->h:Ll2/b1;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    new-instance v0, Lf71/e;

    .line 2
    .line 3
    iget-boolean v4, p0, Lf71/e;->g:Z

    .line 4
    .line 5
    iget-object v5, p0, Lf71/e;->h:Ll2/b1;

    .line 6
    .line 7
    iget-object v1, p0, Lf71/e;->e:Lc1/c;

    .line 8
    .line 9
    iget-wide v2, p0, Lf71/e;->f:J

    .line 10
    .line 11
    move-object v6, p2

    .line 12
    invoke-direct/range {v0 .. v6}, Lf71/e;-><init>(Lc1/c;JZLl2/b1;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
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
    invoke-virtual {p0, p1, p2}, Lf71/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lf71/e;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lf71/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v1, p0, Lf71/e;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x2

    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    if-eq v1, v3, :cond_1

    .line 11
    .line 12
    if-eq v1, v4, :cond_1

    .line 13
    .line 14
    if-ne v1, v2, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    :goto_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    sget p1, Lf71/f;->a:F

    .line 33
    .line 34
    iget-object p1, p0, Lf71/e;->h:Ll2/b1;

    .line 35
    .line 36
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    check-cast p1, Ljava/lang/Boolean;

    .line 41
    .line 42
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_3

    .line 47
    .line 48
    new-instance v6, Ljava/lang/Float;

    .line 49
    .line 50
    const/high16 p1, 0x3f800000    # 1.0f

    .line 51
    .line 52
    invoke-direct {v6, p1}, Ljava/lang/Float;-><init>(F)V

    .line 53
    .line 54
    .line 55
    iget-wide v1, p0, Lf71/e;->f:J

    .line 56
    .line 57
    invoke-static {v1, v2}, Lmy0/c;->e(J)J

    .line 58
    .line 59
    .line 60
    move-result-wide v1

    .line 61
    long-to-int p1, v1

    .line 62
    const/4 v1, 0x0

    .line 63
    sget-object v2, Lc1/z;->d:Lc1/y;

    .line 64
    .line 65
    invoke-static {p1, v1, v2, v4}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    iput v3, p0, Lf71/e;->d:I

    .line 70
    .line 71
    iget-object v5, p0, Lf71/e;->e:Lc1/c;

    .line 72
    .line 73
    const/4 v8, 0x0

    .line 74
    const/4 v9, 0x0

    .line 75
    const/16 v11, 0xc

    .line 76
    .line 77
    move-object v10, p0

    .line 78
    invoke-static/range {v5 .. v11}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-ne p0, v0, :cond_5

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_3
    move-object v10, p0

    .line 86
    iget-boolean p0, v10, Lf71/e;->g:Z

    .line 87
    .line 88
    iget-object p1, v10, Lf71/e;->e:Lc1/c;

    .line 89
    .line 90
    if-eqz p0, :cond_4

    .line 91
    .line 92
    iget-object p0, p1, Lc1/c;->e:Ll2/j1;

    .line 93
    .line 94
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    iput v4, v10, Lf71/e;->d:I

    .line 99
    .line 100
    invoke-virtual {p1, p0, v10}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-ne p0, v0, :cond_5

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    new-instance p0, Ljava/lang/Float;

    .line 108
    .line 109
    const/4 v1, 0x0

    .line 110
    invoke-direct {p0, v1}, Ljava/lang/Float;-><init>(F)V

    .line 111
    .line 112
    .line 113
    iput v2, v10, Lf71/e;->d:I

    .line 114
    .line 115
    invoke-virtual {p1, p0, v10}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v0, :cond_5

    .line 120
    .line 121
    :goto_1
    return-object v0

    .line 122
    :cond_5
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0
.end method

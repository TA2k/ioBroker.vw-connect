.class public final Lc4/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Z

.field public e:I

.field public synthetic f:F

.field public final synthetic g:Lc4/e;


# direct methods
.method public constructor <init>(Lc4/e;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lc4/d;->g:Lc4/e;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Lc4/d;

    .line 2
    .line 3
    iget-object p0, p0, Lc4/d;->g:Lc4/e;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lc4/d;-><init>(Lc4/e;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    check-cast p1, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    iput p0, v0, Lc4/d;->f:F

    .line 15
    .line 16
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Number;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p0, p1, p2}, Lc4/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lc4/d;

    .line 18
    .line 19
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lc4/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lc4/d;->e:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const-wide v3, 0xffffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    iget-boolean p0, p0, Lc4/d;->d:Z

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget p1, p0, Lc4/d;->f:F

    .line 33
    .line 34
    iget-object v1, p0, Lc4/d;->g:Lc4/e;

    .line 35
    .line 36
    iget-object v5, v1, Lc4/e;->a:Ld4/q;

    .line 37
    .line 38
    iget-object v5, v5, Ld4/q;->d:Ld4/l;

    .line 39
    .line 40
    sget-object v6, Ld4/k;->e:Ld4/z;

    .line 41
    .line 42
    iget-object v5, v5, Ld4/l;->d:Landroidx/collection/q0;

    .line 43
    .line 44
    invoke-virtual {v5, v6}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    if-nez v5, :cond_2

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    :cond_2
    check-cast v5, Lay0/n;

    .line 52
    .line 53
    if-eqz v5, :cond_6

    .line 54
    .line 55
    iget-object v1, v1, Lc4/e;->a:Ld4/q;

    .line 56
    .line 57
    iget-object v1, v1, Ld4/q;->d:Ld4/l;

    .line 58
    .line 59
    sget-object v6, Ld4/v;->u:Ld4/z;

    .line 60
    .line 61
    invoke-virtual {v1, v6}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    check-cast v1, Ld4/j;

    .line 66
    .line 67
    iget-boolean v1, v1, Ld4/j;->c:Z

    .line 68
    .line 69
    if-eqz v1, :cond_3

    .line 70
    .line 71
    neg-float p1, p1

    .line 72
    :cond_3
    const/4 v6, 0x0

    .line 73
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    int-to-long v6, v6

    .line 78
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    int-to-long v8, p1

    .line 83
    const/16 p1, 0x20

    .line 84
    .line 85
    shl-long/2addr v6, p1

    .line 86
    and-long/2addr v8, v3

    .line 87
    or-long/2addr v6, v8

    .line 88
    new-instance p1, Ld3/b;

    .line 89
    .line 90
    invoke-direct {p1, v6, v7}, Ld3/b;-><init>(J)V

    .line 91
    .line 92
    .line 93
    iput-boolean v1, p0, Lc4/d;->d:Z

    .line 94
    .line 95
    iput v2, p0, Lc4/d;->e:I

    .line 96
    .line 97
    invoke-interface {v5, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    if-ne p1, v0, :cond_4

    .line 102
    .line 103
    return-object v0

    .line 104
    :cond_4
    move p0, v1

    .line 105
    :goto_0
    check-cast p1, Ld3/b;

    .line 106
    .line 107
    iget-wide v0, p1, Ld3/b;->a:J

    .line 108
    .line 109
    if-eqz p0, :cond_5

    .line 110
    .line 111
    and-long p0, v0, v3

    .line 112
    .line 113
    long-to-int p0, p0

    .line 114
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 115
    .line 116
    .line 117
    move-result p0

    .line 118
    neg-float p0, p0

    .line 119
    goto :goto_1

    .line 120
    :cond_5
    and-long p0, v0, v3

    .line 121
    .line 122
    long-to-int p0, p0

    .line 123
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    :goto_1
    new-instance p1, Ljava/lang/Float;

    .line 128
    .line 129
    invoke-direct {p1, p0}, Ljava/lang/Float;-><init>(F)V

    .line 130
    .line 131
    .line 132
    return-object p1

    .line 133
    :cond_6
    const-string p0, "Required value was null."

    .line 134
    .line 135
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    throw p0
.end method

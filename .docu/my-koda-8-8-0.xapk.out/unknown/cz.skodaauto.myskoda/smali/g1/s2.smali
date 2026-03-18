.class public final Lg1/s2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lg1/u2;

.field public e:Lkotlin/jvm/internal/e0;

.field public f:J

.field public g:I

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lg1/u2;

.field public final synthetic j:Lkotlin/jvm/internal/e0;

.field public final synthetic k:J


# direct methods
.method public constructor <init>(Lg1/u2;Lkotlin/jvm/internal/e0;JLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/s2;->i:Lg1/u2;

    .line 2
    .line 3
    iput-object p2, p0, Lg1/s2;->j:Lkotlin/jvm/internal/e0;

    .line 4
    .line 5
    iput-wide p3, p0, Lg1/s2;->k:J

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lg1/s2;

    .line 2
    .line 3
    iget-object v2, p0, Lg1/s2;->j:Lkotlin/jvm/internal/e0;

    .line 4
    .line 5
    iget-wide v3, p0, Lg1/s2;->k:J

    .line 6
    .line 7
    iget-object v1, p0, Lg1/s2;->i:Lg1/u2;

    .line 8
    .line 9
    move-object v5, p2

    .line 10
    invoke-direct/range {v0 .. v5}, Lg1/s2;-><init>(Lg1/u2;Lkotlin/jvm/internal/e0;JLkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, v0, Lg1/s2;->h:Ljava/lang/Object;

    .line 14
    .line 15
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lg1/t2;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lg1/s2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lg1/s2;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg1/s2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lg1/s2;->g:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    iget-wide v0, p0, Lg1/s2;->f:J

    .line 11
    .line 12
    iget-object v3, p0, Lg1/s2;->e:Lkotlin/jvm/internal/e0;

    .line 13
    .line 14
    iget-object v4, p0, Lg1/s2;->d:Lg1/u2;

    .line 15
    .line 16
    iget-object p0, p0, Lg1/s2;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lg1/u2;

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Lg1/s2;->h:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Lg1/t2;

    .line 38
    .line 39
    new-instance v1, Lg1/k;

    .line 40
    .line 41
    const/4 v3, 0x1

    .line 42
    iget-object v4, p0, Lg1/s2;->i:Lg1/u2;

    .line 43
    .line 44
    invoke-direct {v1, v3, v4, p1}, Lg1/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget-object p1, v4, Lg1/u2;->c:Lg1/j1;

    .line 48
    .line 49
    iget-object v3, p0, Lg1/s2;->j:Lkotlin/jvm/internal/e0;

    .line 50
    .line 51
    iget-wide v5, v3, Lkotlin/jvm/internal/e0;->d:J

    .line 52
    .line 53
    iget-object v7, v4, Lg1/u2;->d:Lg1/w1;

    .line 54
    .line 55
    sget-object v8, Lg1/w1;->e:Lg1/w1;

    .line 56
    .line 57
    iget-wide v9, p0, Lg1/s2;->k:J

    .line 58
    .line 59
    if-ne v7, v8, :cond_2

    .line 60
    .line 61
    invoke-static {v9, v10}, Lt4/q;->b(J)F

    .line 62
    .line 63
    .line 64
    move-result v7

    .line 65
    goto :goto_0

    .line 66
    :cond_2
    invoke-static {v9, v10}, Lt4/q;->c(J)F

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    :goto_0
    invoke-virtual {v4, v7}, Lg1/u2;->d(F)F

    .line 71
    .line 72
    .line 73
    move-result v7

    .line 74
    iput-object v4, p0, Lg1/s2;->h:Ljava/lang/Object;

    .line 75
    .line 76
    iput-object v4, p0, Lg1/s2;->d:Lg1/u2;

    .line 77
    .line 78
    iput-object v3, p0, Lg1/s2;->e:Lkotlin/jvm/internal/e0;

    .line 79
    .line 80
    iput-wide v5, p0, Lg1/s2;->f:J

    .line 81
    .line 82
    iput v2, p0, Lg1/s2;->g:I

    .line 83
    .line 84
    invoke-interface {p1, v1, v7, p0}, Lg1/j1;->a(Lg1/e2;FLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    if-ne p1, v0, :cond_3

    .line 89
    .line 90
    return-object v0

    .line 91
    :cond_3
    move-object p0, v4

    .line 92
    move-wide v0, v5

    .line 93
    :goto_1
    check-cast p1, Ljava/lang/Number;

    .line 94
    .line 95
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    invoke-virtual {p0, p1}, Lg1/u2;->d(F)F

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    iget-object p1, v4, Lg1/u2;->d:Lg1/w1;

    .line 104
    .line 105
    sget-object v4, Lg1/w1;->e:Lg1/w1;

    .line 106
    .line 107
    const/4 v5, 0x0

    .line 108
    if-ne p1, v4, :cond_4

    .line 109
    .line 110
    const/4 p1, 0x2

    .line 111
    invoke-static {v0, v1, p1, p0, v5}, Lt4/q;->a(JIFF)J

    .line 112
    .line 113
    .line 114
    move-result-wide p0

    .line 115
    goto :goto_2

    .line 116
    :cond_4
    invoke-static {v0, v1, v2, v5, p0}, Lt4/q;->a(JIFF)J

    .line 117
    .line 118
    .line 119
    move-result-wide p0

    .line 120
    :goto_2
    iput-wide p0, v3, Lkotlin/jvm/internal/e0;->d:J

    .line 121
    .line 122
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0
.end method

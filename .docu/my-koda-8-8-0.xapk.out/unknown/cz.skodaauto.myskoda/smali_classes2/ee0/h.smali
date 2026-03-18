.class public final Lee0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lee0/a;

.field public final b:Lwr0/e;


# direct methods
.method public constructor <init>(Lee0/a;Lwr0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lee0/h;->a:Lee0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lee0/h;->b:Lwr0/e;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lee0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lee0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lee0/g;

    .line 7
    .line 8
    iget v1, v0, Lee0/g;->f:I

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
    iput v1, v0, Lee0/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lee0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lee0/g;-><init>(Lee0/h;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lee0/g;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lee0/g;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    iget-object v4, p0, Lee0/h;->a:Lee0/a;

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x2

    .line 37
    const/4 v7, 0x1

    .line 38
    if-eqz v2, :cond_4

    .line 39
    .line 40
    if-eq v2, v7, :cond_3

    .line 41
    .line 42
    if-eq v2, v6, :cond_2

    .line 43
    .line 44
    if-ne v2, v5, :cond_1

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-object v3

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
    goto :goto_3

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput v7, v0, Lee0/g;->f:I

    .line 70
    .line 71
    iget-object p0, p0, Lee0/h;->b:Lwr0/e;

    .line 72
    .line 73
    iget-object p0, p0, Lwr0/e;->a:Lwr0/g;

    .line 74
    .line 75
    check-cast p0, Lur0/g;

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v1, :cond_5

    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_5
    :goto_1
    check-cast p1, Lyr0/e;

    .line 85
    .line 86
    if-eqz p1, :cond_6

    .line 87
    .line 88
    iget-object p0, p1, Lyr0/e;->g:Ljava/lang/String;

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_6
    const/4 p0, 0x0

    .line 92
    :goto_2
    if-nez p0, :cond_9

    .line 93
    .line 94
    iput v6, v0, Lee0/g;->f:I

    .line 95
    .line 96
    move-object p0, v4

    .line 97
    check-cast p0, Lce0/b;

    .line 98
    .line 99
    iget-object p0, p0, Lce0/b;->a:Lve0/u;

    .line 100
    .line 101
    const-string p1, "marketing_reconsent_completed_app_version"

    .line 102
    .line 103
    invoke-virtual {p0, p1, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    if-ne p1, v1, :cond_7

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_7
    :goto_3
    if-nez p1, :cond_9

    .line 111
    .line 112
    iput v5, v0, Lee0/g;->f:I

    .line 113
    .line 114
    check-cast v4, Lce0/b;

    .line 115
    .line 116
    iget-object p0, v4, Lce0/b;->a:Lve0/u;

    .line 117
    .line 118
    const-string p1, "marketing_reconsent_required"

    .line 119
    .line 120
    invoke-virtual {p0, v7, p1, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    if-ne p0, v1, :cond_8

    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_8
    move-object p0, v3

    .line 128
    :goto_4
    if-ne p0, v1, :cond_9

    .line 129
    .line 130
    :goto_5
    return-object v1

    .line 131
    :cond_9
    return-object v3
.end method

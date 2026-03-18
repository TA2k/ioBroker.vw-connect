.class public final Loi0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Loi0/e;


# direct methods
.method public constructor <init>(Loi0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Loi0/b;->a:Loi0/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Loi0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Loi0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Loi0/a;

    .line 7
    .line 8
    iget v1, v0, Loi0/a;->g:I

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
    iput v1, v0, Loi0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Loi0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Loi0/a;-><init>(Loi0/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Loi0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Loi0/a;->g:I

    .line 30
    .line 31
    iget-object p0, p0, Loi0/b;->a:Loi0/e;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-boolean p0, v0, Loi0/a;->d:Z

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput v4, v0, Loi0/a;->g:I

    .line 63
    .line 64
    move-object p1, p0

    .line 65
    check-cast p1, Lmi0/a;

    .line 66
    .line 67
    iget-object v2, p1, Lmi0/a;->a:Lve0/u;

    .line 68
    .line 69
    iget-object p1, p1, Lmi0/a;->b:Lpi0/b;

    .line 70
    .line 71
    iget-object p1, p1, Lpi0/b;->c:Lpi0/a;

    .line 72
    .line 73
    iget-object p1, p1, Lpi0/a;->d:Ljava/lang/String;

    .line 74
    .line 75
    const/4 v5, 0x0

    .line 76
    invoke-virtual {v2, v5, p1, v0}, Lve0/u;->d(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    if-ne p1, v1, :cond_4

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 84
    .line 85
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    if-nez p1, :cond_7

    .line 90
    .line 91
    iput-boolean p1, v0, Loi0/a;->d:Z

    .line 92
    .line 93
    iput v3, v0, Loi0/a;->g:I

    .line 94
    .line 95
    check-cast p0, Lmi0/a;

    .line 96
    .line 97
    iget-object v2, p0, Lmi0/a;->a:Lve0/u;

    .line 98
    .line 99
    iget-object p0, p0, Lmi0/a;->b:Lpi0/b;

    .line 100
    .line 101
    iget-object p0, p0, Lpi0/b;->c:Lpi0/a;

    .line 102
    .line 103
    iget-object p0, p0, Lpi0/a;->d:Ljava/lang/String;

    .line 104
    .line 105
    invoke-virtual {v2, v4, p0, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    if-ne p0, v1, :cond_5

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    :goto_2
    if-ne p0, v1, :cond_6

    .line 115
    .line 116
    :goto_3
    return-object v1

    .line 117
    :cond_6
    move p0, p1

    .line 118
    :goto_4
    move p1, p0

    .line 119
    :cond_7
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0
.end method

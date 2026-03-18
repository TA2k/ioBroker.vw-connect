.class public final Lcr0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lam0/c;


# direct methods
.method public constructor <init>(Lam0/c;Lar0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcr0/e;->a:Lam0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lcr0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcr0/e;->b(Lcr0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lcr0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lcr0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lcr0/d;

    .line 7
    .line 8
    iget v1, v0, Lcr0/d;->g:I

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
    iput v1, v0, Lcr0/d;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcr0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lcr0/d;-><init>(Lcr0/e;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lcr0/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcr0/d;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lcr0/d;->d:Lcr0/c;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lcr0/d;->d:Lcr0/c;

    .line 54
    .line 55
    iput v3, v0, Lcr0/d;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lcr0/e;->a:Lam0/c;

    .line 58
    .line 59
    invoke-virtual {p0, v0}, Lam0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    if-ne p2, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p2, Lcm0/b;

    .line 67
    .line 68
    const-string p0, "environment"

    .line 69
    .line 70
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-eqz p0, :cond_6

    .line 78
    .line 79
    if-eq p0, v3, :cond_6

    .line 80
    .line 81
    const/4 p2, 0x2

    .line 82
    if-eq p0, p2, :cond_5

    .line 83
    .line 84
    const/4 p2, 0x3

    .line 85
    if-eq p0, p2, :cond_5

    .line 86
    .line 87
    const/4 p2, 0x4

    .line 88
    if-ne p0, p2, :cond_4

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_4
    new-instance p0, La8/r0;

    .line 92
    .line 93
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_5
    :goto_2
    const-string p0, "https://skoda-connect.qs-shop-volkswagen-we.com/cart"

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_6
    const-string p0, "https://shop.skoda-connect.com/cart"

    .line 101
    .line 102
    :goto_3
    iget-boolean p1, p1, Lcr0/c;->a:Z

    .line 103
    .line 104
    if-eqz p1, :cond_7

    .line 105
    .line 106
    const-string p1, "?preserveCart=true"

    .line 107
    .line 108
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    :cond_7
    return-object p0
.end method

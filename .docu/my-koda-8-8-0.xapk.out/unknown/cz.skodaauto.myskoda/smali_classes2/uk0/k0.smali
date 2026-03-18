.class public final Luk0/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lpp0/k1;

.field public final b:Luk0/w;


# direct methods
.method public constructor <init>(Lpp0/k1;Luk0/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/k0;->a:Lpp0/k1;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/k0;->b:Luk0/w;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvk0/j0;

    .line 2
    .line 3
    invoke-static {p1}, Llp/rb;->b(Lvk0/j0;)Lqp0/b0;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Luk0/k0;->b(Lqp0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final b(Lqp0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Luk0/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Luk0/j0;

    .line 7
    .line 8
    iget v1, v0, Luk0/j0;->f:I

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
    iput v1, v0, Luk0/j0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luk0/j0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Luk0/j0;-><init>(Luk0/k0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Luk0/j0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luk0/j0;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Luk0/j0;->f:I

    .line 52
    .line 53
    iget-object p2, p0, Luk0/k0;->a:Lpp0/k1;

    .line 54
    .line 55
    invoke-virtual {p2, p1, v0}, Lpp0/k1;->d(Lqp0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    if-ne p2, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    check-cast p2, Lne0/t;

    .line 63
    .line 64
    instance-of p1, p2, Lne0/e;

    .line 65
    .line 66
    if-eqz p1, :cond_4

    .line 67
    .line 68
    move-object p1, p2

    .line 69
    check-cast p1, Lne0/e;

    .line 70
    .line 71
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p1, Llx0/b0;

    .line 74
    .line 75
    iget-object p0, p0, Luk0/k0;->b:Luk0/w;

    .line 76
    .line 77
    check-cast p0, Liy/b;

    .line 78
    .line 79
    sget-object p1, Lly/b;->V1:Lly/b;

    .line 80
    .line 81
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 82
    .line 83
    .line 84
    :cond_4
    return-object p2
.end method

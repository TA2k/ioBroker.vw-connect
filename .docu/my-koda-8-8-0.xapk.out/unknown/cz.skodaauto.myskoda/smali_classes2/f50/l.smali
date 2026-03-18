.class public final Lf50/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lpp0/b1;

.field public final b:Lpp0/o1;

.field public final c:Lf50/n;


# direct methods
.method public constructor <init>(Lpp0/b1;Lpp0/o1;Lf50/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf50/l;->a:Lpp0/b1;

    .line 5
    .line 6
    iput-object p2, p0, Lf50/l;->b:Lpp0/o1;

    .line 7
    .line 8
    iput-object p3, p0, Lf50/l;->c:Lf50/n;

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
    invoke-virtual {p0, p2}, Lf50/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lf50/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lf50/k;

    .line 7
    .line 8
    iget v1, v0, Lf50/k;->f:I

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
    iput v1, v0, Lf50/k;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lf50/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lf50/k;-><init>(Lf50/l;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lf50/k;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lf50/k;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p1, p0, Lf50/l;->a:Lpp0/b1;

    .line 52
    .line 53
    iget-object p1, p1, Lpp0/b1;->a:Lpp0/c0;

    .line 54
    .line 55
    check-cast p1, Lnp0/b;

    .line 56
    .line 57
    iput-boolean v3, p1, Lnp0/b;->a:Z

    .line 58
    .line 59
    iput v3, v0, Lf50/k;->f:I

    .line 60
    .line 61
    iget-object p1, p0, Lf50/l;->b:Lpp0/o1;

    .line 62
    .line 63
    invoke-virtual {p1, v0}, Lpp0/o1;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    if-ne p1, v1, :cond_3

    .line 68
    .line 69
    return-object v1

    .line 70
    :cond_3
    :goto_1
    iget-object p0, p0, Lf50/l;->c:Lf50/n;

    .line 71
    .line 72
    check-cast p0, Liy/b;

    .line 73
    .line 74
    sget-object p1, Lly/b;->W1:Lly/b;

    .line 75
    .line 76
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 77
    .line 78
    .line 79
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object p0
.end method

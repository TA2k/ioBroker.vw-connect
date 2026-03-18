.class public final Lg1/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lg1/m;

.field public final synthetic g:Lkotlin/jvm/internal/c0;

.field public final synthetic h:F


# direct methods
.method public constructor <init>(Lg1/m;Lkotlin/jvm/internal/c0;FLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/l;->f:Lg1/m;

    .line 2
    .line 3
    iput-object p2, p0, Lg1/l;->g:Lkotlin/jvm/internal/c0;

    .line 4
    .line 5
    iput p3, p0, Lg1/l;->h:F

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lg1/p;

    .line 2
    .line 3
    check-cast p2, Lg1/z;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    new-instance p2, Lg1/l;

    .line 8
    .line 9
    iget-object v0, p0, Lg1/l;->g:Lkotlin/jvm/internal/c0;

    .line 10
    .line 11
    iget v1, p0, Lg1/l;->h:F

    .line 12
    .line 13
    iget-object p0, p0, Lg1/l;->f:Lg1/m;

    .line 14
    .line 15
    invoke-direct {p2, p0, v0, v1, p3}, Lg1/l;-><init>(Lg1/m;Lkotlin/jvm/internal/c0;FLkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p2, Lg1/l;->e:Ljava/lang/Object;

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {p2, p0}, Lg1/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lg1/l;->d:I

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
    iget-object p0, p0, Lg1/l;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lkotlin/jvm/internal/c0;

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lg1/l;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p1, Lg1/p;

    .line 32
    .line 33
    new-instance v1, Lg1/k;

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    iget-object v4, p0, Lg1/l;->f:Lg1/m;

    .line 37
    .line 38
    invoke-direct {v1, v3, v4, p1}, Lg1/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, v4, Lg1/m;->F:Lg1/j1;

    .line 42
    .line 43
    if-eqz p1, :cond_3

    .line 44
    .line 45
    iget-object v3, p0, Lg1/l;->g:Lkotlin/jvm/internal/c0;

    .line 46
    .line 47
    iput-object v3, p0, Lg1/l;->e:Ljava/lang/Object;

    .line 48
    .line 49
    iput v2, p0, Lg1/l;->d:I

    .line 50
    .line 51
    iget v2, p0, Lg1/l;->h:F

    .line 52
    .line 53
    invoke-interface {p1, v1, v2, p0}, Lg1/j1;->a(Lg1/e2;FLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-ne p1, v0, :cond_2

    .line 58
    .line 59
    return-object v0

    .line 60
    :cond_2
    move-object p0, v3

    .line 61
    :goto_0
    check-cast p1, Ljava/lang/Number;

    .line 62
    .line 63
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    iput p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 68
    .line 69
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object p0

    .line 72
    :cond_3
    const-string p0, "resolvedFlingBehavior"

    .line 73
    .line 74
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const/4 p0, 0x0

    .line 78
    throw p0
.end method

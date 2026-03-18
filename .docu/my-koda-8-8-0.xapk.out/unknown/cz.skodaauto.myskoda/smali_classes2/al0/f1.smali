.class public final Lal0/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwj0/g;

.field public final b:Lal0/d0;


# direct methods
.method public constructor <init>(Lwj0/g;Lal0/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/f1;->a:Lwj0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/f1;->b:Lal0/d0;

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
    invoke-virtual {p0, p2}, Lal0/f1;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lal0/e1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lal0/e1;

    .line 7
    .line 8
    iget v1, v0, Lal0/e1;->f:I

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
    iput v1, v0, Lal0/e1;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lal0/e1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lal0/e1;-><init>(Lal0/f1;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lal0/e1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lal0/e1;->f:I

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
    iput v3, v0, Lal0/e1;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lal0/f1;->a:Lwj0/g;

    .line 54
    .line 55
    iget-object p1, p1, Lwj0/g;->a:Lwj0/a;

    .line 56
    .line 57
    check-cast p1, Luj0/c;

    .line 58
    .line 59
    iget-object p1, p1, Luj0/c;->d:Lyy0/l1;

    .line 60
    .line 61
    invoke-static {p1, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p1, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p1, Lxj0/b;

    .line 69
    .line 70
    iget-object p1, p1, Lxj0/b;->a:Lxj0/f;

    .line 71
    .line 72
    iget-object p0, p0, Lal0/f1;->b:Lal0/d0;

    .line 73
    .line 74
    check-cast p0, Lyk0/f;

    .line 75
    .line 76
    iget-object p0, p0, Lyk0/f;->b:Lyy0/q1;

    .line 77
    .line 78
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0
.end method

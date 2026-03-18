.class public final Lcc0/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lcm0/d;

.field public synthetic f:Z

.field public final synthetic g:Lcc0/d;


# direct methods
.method public constructor <init>(Lcc0/d;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcc0/c;->g:Lcc0/d;

    .line 2
    .line 3
    const/4 p1, 0x3

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lcm0/d;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    new-instance v0, Lcc0/c;

    .line 12
    .line 13
    iget-object p0, p0, Lcc0/c;->g:Lcc0/d;

    .line 14
    .line 15
    invoke-direct {v0, p0, p3}, Lcc0/c;-><init>(Lcc0/d;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lcc0/c;->e:Lcm0/d;

    .line 19
    .line 20
    iput-boolean p2, v0, Lcc0/c;->f:Z

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lcc0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lcc0/c;->e:Lcm0/d;

    .line 2
    .line 3
    iget-boolean v1, p0, Lcc0/c;->f:Z

    .line 4
    .line 5
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v3, p0, Lcc0/c;->d:I

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    if-eqz v3, :cond_1

    .line 11
    .line 12
    if-ne v3, v4, :cond_0

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
    sget-object p1, Lcm0/d;->d:Lcm0/d;

    .line 30
    .line 31
    if-ne v0, p1, :cond_3

    .line 32
    .line 33
    if-nez v1, :cond_3

    .line 34
    .line 35
    iget-object p1, p0, Lcc0/c;->g:Lcc0/d;

    .line 36
    .line 37
    iget-object p1, p1, Lcc0/d;->b:Lcc0/a;

    .line 38
    .line 39
    const/4 v0, 0x0

    .line 40
    iput-object v0, p0, Lcc0/c;->e:Lcm0/d;

    .line 41
    .line 42
    iput-boolean v1, p0, Lcc0/c;->f:Z

    .line 43
    .line 44
    iput v4, p0, Lcc0/c;->d:I

    .line 45
    .line 46
    check-cast p1, Lac0/w;

    .line 47
    .line 48
    iget-object v3, p1, Lac0/w;->j:Lpx0/g;

    .line 49
    .line 50
    new-instance v5, Lac0/n;

    .line 51
    .line 52
    const/4 v6, 0x0

    .line 53
    invoke-direct {v5, p1, v0, v6}, Lac0/n;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v3, v5, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    if-ne p1, v2, :cond_2

    .line 61
    .line 62
    return-object v2

    .line 63
    :cond_2
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 64
    .line 65
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    if-eqz p0, :cond_3

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_3
    const/4 v4, 0x0

    .line 73
    :goto_1
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    new-instance v0, Llx0/l;

    .line 82
    .line 83
    invoke-direct {v0, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    return-object v0
.end method

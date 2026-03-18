.class public final Lwz0/x;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public e:I

.field public synthetic f:Llx0/b;

.field public final synthetic g:Lin/o;


# direct methods
.method public constructor <init>(Lin/o;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lwz0/x;->g:Lin/o;

    .line 2
    .line 3
    const/4 p1, 0x3

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b;

    .line 2
    .line 3
    check-cast p2, Llx0/b0;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    new-instance p2, Lwz0/x;

    .line 8
    .line 9
    iget-object p0, p0, Lwz0/x;->g:Lin/o;

    .line 10
    .line 11
    invoke-direct {p2, p0, p3}, Lwz0/x;-><init>(Lin/o;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p2, Lwz0/x;->f:Llx0/b;

    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p2, p0}, Lwz0/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Lwz0/x;->g:Lin/o;

    .line 2
    .line 3
    iget-object v1, v0, Lin/o;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lo8/j;

    .line 6
    .line 7
    iget-object v2, p0, Lwz0/x;->f:Llx0/b;

    .line 8
    .line 9
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    iget v4, p0, Lwz0/x;->e:I

    .line 12
    .line 13
    const/4 v5, 0x1

    .line 14
    if-eqz v4, :cond_1

    .line 15
    .line 16
    if-ne v4, v5, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Lo8/j;->x()B

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    if-ne p1, v5, :cond_2

    .line 38
    .line 39
    invoke-virtual {v0, v5}, Lin/o;->l(Z)Lvz0/e0;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :cond_2
    const/4 v4, 0x0

    .line 45
    if-nez p1, :cond_3

    .line 46
    .line 47
    invoke-virtual {v0, v4}, Lin/o;->l(Z)Lvz0/e0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :cond_3
    const/4 v6, 0x6

    .line 53
    const/4 v7, 0x0

    .line 54
    if-ne p1, v6, :cond_5

    .line 55
    .line 56
    iput-object v7, p0, Lwz0/x;->f:Llx0/b;

    .line 57
    .line 58
    iput v5, p0, Lwz0/x;->e:I

    .line 59
    .line 60
    invoke-static {v0, v2, p0}, Lin/o;->d(Lin/o;Llx0/b;Lrx0/a;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p1, v3, :cond_4

    .line 65
    .line 66
    return-object v3

    .line 67
    :cond_4
    :goto_0
    check-cast p1, Lvz0/n;

    .line 68
    .line 69
    return-object p1

    .line 70
    :cond_5
    const/16 p0, 0x8

    .line 71
    .line 72
    if-ne p1, p0, :cond_6

    .line 73
    .line 74
    invoke-virtual {v0}, Lin/o;->k()Lvz0/f;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :cond_6
    const-string p0, "Can\'t begin reading element, unexpected token"

    .line 80
    .line 81
    invoke-static {v1, p0, v4, v7, v6}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 82
    .line 83
    .line 84
    throw v7
.end method

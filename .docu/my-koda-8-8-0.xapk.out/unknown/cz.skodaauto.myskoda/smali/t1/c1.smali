.class public final Lt1/c1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lg1/z1;

.field public synthetic f:J

.field public final synthetic g:Lvy0/b0;

.field public final synthetic h:Ll2/b1;

.field public final synthetic i:Li1/l;


# direct methods
.method public constructor <init>(Lvy0/b0;Ll2/b1;Li1/l;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lt1/c1;->g:Lvy0/b0;

    .line 2
    .line 3
    iput-object p2, p0, Lt1/c1;->h:Ll2/b1;

    .line 4
    .line 5
    iput-object p3, p0, Lt1/c1;->i:Li1/l;

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
    .locals 4

    .line 1
    check-cast p1, Lg1/z1;

    .line 2
    .line 3
    check-cast p2, Ld3/b;

    .line 4
    .line 5
    iget-wide v0, p2, Ld3/b;->a:J

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    new-instance p2, Lt1/c1;

    .line 10
    .line 11
    iget-object v2, p0, Lt1/c1;->h:Ll2/b1;

    .line 12
    .line 13
    iget-object v3, p0, Lt1/c1;->i:Li1/l;

    .line 14
    .line 15
    iget-object p0, p0, Lt1/c1;->g:Lvy0/b0;

    .line 16
    .line 17
    invoke-direct {p2, p0, v2, v3, p3}, Lt1/c1;-><init>(Lvy0/b0;Ll2/b1;Li1/l;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p2, Lt1/c1;->e:Lg1/z1;

    .line 21
    .line 22
    iput-wide v0, p2, Lt1/c1;->f:J

    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {p2, p0}, Lt1/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lt1/c1;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    iget-object v3, p0, Lt1/c1;->g:Lvy0/b0;

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x1

    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    if-ne v1, v5, :cond_0

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
    iget-object p1, p0, Lt1/c1;->e:Lg1/z1;

    .line 30
    .line 31
    iget-wide v8, p0, Lt1/c1;->f:J

    .line 32
    .line 33
    new-instance v6, Le1/b;

    .line 34
    .line 35
    const/4 v11, 0x0

    .line 36
    const/4 v12, 0x7

    .line 37
    iget-object v7, p0, Lt1/c1;->h:Ll2/b1;

    .line 38
    .line 39
    iget-object v10, p0, Lt1/c1;->i:Li1/l;

    .line 40
    .line 41
    invoke-direct/range {v6 .. v12}, Le1/b;-><init>(Ljava/lang/Object;JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {v3, v4, v4, v6, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 45
    .line 46
    .line 47
    iput v5, p0, Lt1/c1;->d:I

    .line 48
    .line 49
    invoke-virtual {p1, p0}, Lg1/z1;->f(Lrx0/c;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    if-ne p1, v0, :cond_2

    .line 54
    .line 55
    return-object v0

    .line 56
    :cond_2
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    new-instance v0, Lau0/b;

    .line 63
    .line 64
    iget-object v1, p0, Lt1/c1;->h:Ll2/b1;

    .line 65
    .line 66
    iget-object p0, p0, Lt1/c1;->i:Li1/l;

    .line 67
    .line 68
    invoke-direct {v0, v1, p1, p0, v4}, Lau0/b;-><init>(Ll2/b1;ZLi1/l;Lkotlin/coroutines/Continuation;)V

    .line 69
    .line 70
    .line 71
    invoke-static {v3, v4, v4, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 72
    .line 73
    .line 74
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0
.end method

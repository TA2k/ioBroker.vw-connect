.class public final Le1/z;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lg1/z1;

.field public synthetic f:J

.field public final synthetic g:Le1/a0;


# direct methods
.method public constructor <init>(Le1/a0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Le1/z;->g:Le1/a0;

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
    .locals 2

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
    new-instance p2, Le1/z;

    .line 10
    .line 11
    iget-object p0, p0, Le1/z;->g:Le1/a0;

    .line 12
    .line 13
    invoke-direct {p2, p0, p3}, Le1/z;-><init>(Le1/a0;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p2, Le1/z;->e:Lg1/z1;

    .line 17
    .line 18
    iput-wide v0, p2, Le1/z;->f:J

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {p2, p0}, Le1/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Le1/z;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    if-ne v1, v3, :cond_0

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iget-object v4, p0, Le1/z;->e:Lg1/z1;

    .line 28
    .line 29
    iget-wide v5, p0, Le1/z;->f:J

    .line 30
    .line 31
    iget-object v8, p0, Le1/z;->g:Le1/a0;

    .line 32
    .line 33
    iget-boolean p1, v8, Le1/h;->y:Z

    .line 34
    .line 35
    if-eqz p1, :cond_3

    .line 36
    .line 37
    iput v3, p0, Le1/z;->d:I

    .line 38
    .line 39
    iget-object v7, v8, Le1/h;->t:Li1/l;

    .line 40
    .line 41
    if-eqz v7, :cond_2

    .line 42
    .line 43
    new-instance v3, Le1/c;

    .line 44
    .line 45
    const/4 v9, 0x0

    .line 46
    invoke-direct/range {v3 .. v9}, Le1/c;-><init>(Lg1/z1;JLi1/l;Le1/h;Lkotlin/coroutines/Continuation;)V

    .line 47
    .line 48
    .line 49
    invoke-static {v3, p0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    if-ne p0, v0, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    move-object p0, v2

    .line 57
    :goto_0
    if-ne p0, v0, :cond_3

    .line 58
    .line 59
    return-object v0

    .line 60
    :cond_3
    :goto_1
    return-object v2
.end method

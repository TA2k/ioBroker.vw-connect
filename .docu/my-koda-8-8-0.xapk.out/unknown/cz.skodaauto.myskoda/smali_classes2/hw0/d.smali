.class public final Lhw0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public d:I

.field public synthetic e:Lkw0/c;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:Ljava/util/Set;

.field public final synthetic i:Lgw0/b;


# direct methods
.method public constructor <init>(Lgw0/b;Ljava/util/List;Ljava/util/Set;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lhw0/d;->g:Ljava/util/List;

    .line 2
    .line 3
    iput-object p3, p0, Lhw0/d;->h:Ljava/util/Set;

    .line 4
    .line 5
    iput-object p1, p0, Lhw0/d;->i:Lgw0/b;

    .line 6
    .line 7
    const/4 p1, 0x5

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lgw0/i;

    .line 2
    .line 3
    check-cast p2, Lkw0/c;

    .line 4
    .line 5
    check-cast p4, Lzw0/a;

    .line 6
    .line 7
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    new-instance p1, Lhw0/d;

    .line 10
    .line 11
    iget-object p4, p0, Lhw0/d;->h:Ljava/util/Set;

    .line 12
    .line 13
    iget-object v0, p0, Lhw0/d;->i:Lgw0/b;

    .line 14
    .line 15
    iget-object p0, p0, Lhw0/d;->g:Ljava/util/List;

    .line 16
    .line 17
    invoke-direct {p1, v0, p0, p4, p5}, Lhw0/d;-><init>(Lgw0/b;Ljava/util/List;Ljava/util/Set;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    iput-object p2, p1, Lhw0/d;->e:Lkw0/c;

    .line 21
    .line 22
    iput-object p3, p1, Lhw0/d;->f:Ljava/lang/Object;

    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {p1, p0}, Lhw0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v3, p0, Lhw0/d;->e:Lkw0/c;

    .line 2
    .line 3
    iget-object v4, p0, Lhw0/d;->f:Ljava/lang/Object;

    .line 4
    .line 5
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v0, p0, Lhw0/d;->d:I

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-object p1

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
    const/4 p1, 0x0

    .line 30
    iput-object p1, p0, Lhw0/d;->e:Lkw0/c;

    .line 31
    .line 32
    iput-object p1, p0, Lhw0/d;->f:Ljava/lang/Object;

    .line 33
    .line 34
    iput v1, p0, Lhw0/d;->d:I

    .line 35
    .line 36
    iget-object v0, p0, Lhw0/d;->g:Ljava/util/List;

    .line 37
    .line 38
    iget-object v1, p0, Lhw0/d;->h:Ljava/util/Set;

    .line 39
    .line 40
    iget-object v2, p0, Lhw0/d;->i:Lgw0/b;

    .line 41
    .line 42
    move-object v5, p0

    .line 43
    invoke-static/range {v0 .. v5}, Lhw0/h;->a(Ljava/util/List;Ljava/util/Set;Lgw0/b;Lkw0/c;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    if-ne p0, v6, :cond_2

    .line 48
    .line 49
    return-object v6

    .line 50
    :cond_2
    return-object p0
.end method

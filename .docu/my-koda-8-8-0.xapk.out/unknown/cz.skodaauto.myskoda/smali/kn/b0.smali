.class public final Lkn/b0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public final synthetic e:Z

.field public final synthetic f:Lkn/c0;

.field public final synthetic g:Lkn/f0;

.field public final synthetic h:Lc1/j;


# direct methods
.method public constructor <init>(ZLkn/c0;Lkn/f0;Lc1/j;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lkn/b0;->e:Z

    .line 2
    .line 3
    iput-object p2, p0, Lkn/b0;->f:Lkn/c0;

    .line 4
    .line 5
    iput-object p3, p0, Lkn/b0;->g:Lkn/f0;

    .line 6
    .line 7
    iput-object p4, p0, Lkn/b0;->h:Lc1/j;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lkn/b0;

    .line 2
    .line 3
    iget-object v3, p0, Lkn/b0;->g:Lkn/f0;

    .line 4
    .line 5
    iget-object v4, p0, Lkn/b0;->h:Lc1/j;

    .line 6
    .line 7
    iget-boolean v1, p0, Lkn/b0;->e:Z

    .line 8
    .line 9
    iget-object v2, p0, Lkn/b0;->f:Lkn/c0;

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Lkn/b0;-><init>(ZLkn/c0;Lkn/f0;Lc1/j;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Lkn/b0;->d:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lkn/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lkn/b0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lkn/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lkn/b0;->d:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lvy0/b0;

    .line 9
    .line 10
    new-instance v0, Lau0/b;

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    const/4 v6, 0x4

    .line 14
    iget-boolean v1, p0, Lkn/b0;->e:Z

    .line 15
    .line 16
    iget-object v2, p0, Lkn/b0;->f:Lkn/c0;

    .line 17
    .line 18
    iget-object v3, p0, Lkn/b0;->g:Lkn/f0;

    .line 19
    .line 20
    iget-object v4, p0, Lkn/b0;->h:Lc1/j;

    .line 21
    .line 22
    invoke-direct/range {v0 .. v6}, Lau0/b;-><init>(ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    const/4 p0, 0x3

    .line 26
    const/4 v1, 0x0

    .line 27
    invoke-static {p1, v1, v1, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

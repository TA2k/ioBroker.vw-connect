.class public final Le71/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public constructor <init>(ZLay0/a;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Le71/d;->d:Z

    .line 2
    .line 3
    iput-object p2, p0, Le71/d;->e:Lay0/a;

    .line 4
    .line 5
    iput-object p3, p0, Le71/d;->f:Ll2/b1;

    .line 6
    .line 7
    iput-object p4, p0, Le71/d;->g:Ll2/b1;

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
    new-instance v0, Le71/d;

    .line 2
    .line 3
    iget-object v3, p0, Le71/d;->f:Ll2/b1;

    .line 4
    .line 5
    iget-object v4, p0, Le71/d;->g:Ll2/b1;

    .line 6
    .line 7
    iget-boolean v1, p0, Le71/d;->d:Z

    .line 8
    .line 9
    iget-object v2, p0, Le71/d;->e:Lay0/a;

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Le71/d;-><init>(ZLay0/a;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
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
    invoke-virtual {p0, p1, p2}, Le71/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Le71/d;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Le71/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-boolean p1, p0, Le71/d;->d:Z

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v1, p0, Le71/d;->f:Ll2/b1;

    .line 13
    .line 14
    invoke-interface {v1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Le71/d;->g:Ll2/b1;

    .line 18
    .line 19
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    check-cast v1, Ljava/lang/Boolean;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    if-nez p1, :cond_0

    .line 32
    .line 33
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 34
    .line 35
    invoke-interface {v0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Le71/d;->e:Lay0/a;

    .line 39
    .line 40
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0
.end method

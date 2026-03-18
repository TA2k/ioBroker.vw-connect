.class public final Lwe/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public synthetic d:Ljava/lang/String;

.field public synthetic e:Z

.field public synthetic f:Z

.field public synthetic g:Llc/l;

.field public final synthetic h:Lwe/f;


# direct methods
.method public constructor <init>(Lwe/f;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lwe/e;->h:Lwe/f;

    .line 2
    .line 3
    const/4 p1, 0x5

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Ljava/lang/String;

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
    check-cast p3, Ljava/lang/Boolean;

    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 12
    .line 13
    .line 14
    move-result p3

    .line 15
    check-cast p4, Llc/l;

    .line 16
    .line 17
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 18
    .line 19
    new-instance v0, Lwe/e;

    .line 20
    .line 21
    iget-object p0, p0, Lwe/e;->h:Lwe/f;

    .line 22
    .line 23
    invoke-direct {v0, p0, p5}, Lwe/e;-><init>(Lwe/f;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    iput-object p1, v0, Lwe/e;->d:Ljava/lang/String;

    .line 27
    .line 28
    iput-boolean p2, v0, Lwe/e;->e:Z

    .line 29
    .line 30
    iput-boolean p3, v0, Lwe/e;->f:Z

    .line 31
    .line 32
    iput-object p4, v0, Lwe/e;->g:Llc/l;

    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    invoke-virtual {v0, p0}, Lwe/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v2, p0, Lwe/e;->d:Ljava/lang/String;

    .line 2
    .line 3
    iget-boolean v3, p0, Lwe/e;->e:Z

    .line 4
    .line 5
    iget-boolean v6, p0, Lwe/e;->f:Z

    .line 6
    .line 7
    iget-object v4, p0, Lwe/e;->g:Llc/l;

    .line 8
    .line 9
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lwe/e;->h:Lwe/f;

    .line 15
    .line 16
    iget-object p0, p0, Lwe/f;->d:Lje/r;

    .line 17
    .line 18
    iget-object v1, p0, Lje/r;->c:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-lez p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    :goto_0
    move v5, p0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    goto :goto_0

    .line 31
    :goto_1
    new-instance v0, Lwe/d;

    .line 32
    .line 33
    invoke-direct/range {v0 .. v6}, Lwe/d;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlc/l;ZZ)V

    .line 34
    .line 35
    .line 36
    return-object v0
.end method

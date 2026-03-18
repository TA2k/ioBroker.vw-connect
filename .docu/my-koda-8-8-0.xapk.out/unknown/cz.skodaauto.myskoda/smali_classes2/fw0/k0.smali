.class public final Lfw0/k0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public synthetic d:Lkw0/c;

.field public final synthetic e:I


# direct methods
.method public constructor <init>(ILkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lfw0/k0;->e:I

    .line 2
    .line 3
    const/4 p1, 0x4

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgw0/f;

    .line 2
    .line 3
    check-cast p2, Lkw0/c;

    .line 4
    .line 5
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    new-instance p1, Lfw0/k0;

    .line 8
    .line 9
    iget p0, p0, Lfw0/k0;->e:I

    .line 10
    .line 11
    invoke-direct {p1, p0, p4}, Lfw0/k0;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    iput-object p2, p1, Lfw0/k0;->d:Lkw0/c;

    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Lfw0/k0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lfw0/k0;->d:Lkw0/c;

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p1, v0, Lkw0/c;->f:Lvw0/d;

    .line 9
    .line 10
    sget-object v1, Lfw0/n0;->c:Lvw0/a;

    .line 11
    .line 12
    invoke-virtual {p1, v1}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Ljava/lang/Integer;

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget p0, p0, Lfw0/k0;->e:I

    .line 26
    .line 27
    :goto_0
    iget-object p1, v0, Lkw0/c;->f:Lvw0/d;

    .line 28
    .line 29
    new-instance v0, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, v1, v0}, Lvw0/d;->e(Lvw0/a;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0
.end method

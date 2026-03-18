.class public final Lh2/g6;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public synthetic d:F

.field public final synthetic e:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh2/g6;->e:Lay0/k;

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
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    new-instance p2, Lh2/g6;

    .line 12
    .line 13
    iget-object p0, p0, Lh2/g6;->e:Lay0/k;

    .line 14
    .line 15
    invoke-direct {p2, p0, p3}, Lh2/g6;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    iput p1, p2, Lh2/g6;->d:F

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {p2, p0}, Lh2/g6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget p1, p0, Lh2/g6;->d:F

    .line 7
    .line 8
    new-instance v0, Ljava/lang/Float;

    .line 9
    .line 10
    invoke-direct {v0, p1}, Ljava/lang/Float;-><init>(F)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lh2/g6;->e:Lay0/k;

    .line 14
    .line 15
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0
.end method

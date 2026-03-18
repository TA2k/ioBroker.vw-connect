.class public final Lcl0/v;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lal0/f1;

.field public final j:Lrq0/f;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lal0/x;Ltr0/b;Lal0/f1;Lrq0/f;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lcl0/t;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcl0/t;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Lcl0/v;->h:Ltr0/b;

    .line 12
    .line 13
    iput-object p3, p0, Lcl0/v;->i:Lal0/f1;

    .line 14
    .line 15
    iput-object p4, p0, Lcl0/v;->j:Lrq0/f;

    .line 16
    .line 17
    iput-object p5, p0, Lcl0/v;->k:Lij0/a;

    .line 18
    .line 19
    invoke-virtual {p1}, Lal0/x;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    check-cast p1, Lbl0/l0;

    .line 24
    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    check-cast p2, Lcl0/t;

    .line 32
    .line 33
    iget-object p1, p1, Lbl0/l0;->a:Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    new-instance p2, Lcl0/t;

    .line 39
    .line 40
    invoke-direct {p2, p1}, Lcl0/t;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    new-instance p2, Lcl0/u;

    .line 51
    .line 52
    const/4 p3, 0x1

    .line 53
    const/4 p4, 0x0

    .line 54
    invoke-direct {p2, p0, p4, p3}, Lcl0/u;-><init>(Lcl0/v;Lkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    const/4 p0, 0x3

    .line 58
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 59
    .line 60
    .line 61
    return-void
.end method

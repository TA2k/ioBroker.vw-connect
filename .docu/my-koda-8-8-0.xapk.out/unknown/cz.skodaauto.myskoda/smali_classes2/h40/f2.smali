.class public final Lh40/f2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lf40/m0;

.field public final i:Lf40/o0;


# direct methods
.method public constructor <init>(Lf40/l0;Lij0/a;Lf40/m0;Lf40/o0;)V
    .locals 2

    .line 1
    new-instance v0, Lh40/e2;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lh40/e2;-><init>(Lh40/k3;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p3, p0, Lh40/f2;->h:Lf40/m0;

    .line 11
    .line 12
    iput-object p4, p0, Lh40/f2;->i:Lf40/o0;

    .line 13
    .line 14
    invoke-virtual {p1}, Lf40/l0;->invoke()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    check-cast p1, Lg40/d0;

    .line 19
    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 23
    .line 24
    .line 25
    move-result-object p3

    .line 26
    check-cast p3, Lh40/e2;

    .line 27
    .line 28
    new-instance p4, Lh40/k3;

    .line 29
    .line 30
    iget-object p1, p1, Lg40/d0;->m:Ljava/time/LocalDate;

    .line 31
    .line 32
    invoke-static {p1}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    check-cast p2, Ljj0/f;

    .line 41
    .line 42
    const v0, 0x7f120c9e

    .line 43
    .line 44
    .line 45
    invoke-virtual {p2, v0, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-direct {p4, p1}, Lh40/k3;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    new-instance p1, Lh40/e2;

    .line 56
    .line 57
    invoke-direct {p1, p4}, Lh40/e2;-><init>(Lh40/k3;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 61
    .line 62
    .line 63
    :cond_0
    return-void
.end method

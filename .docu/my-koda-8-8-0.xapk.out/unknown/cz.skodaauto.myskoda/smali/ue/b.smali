.class public final Lue/b;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lt10/k;

.field public final e:Lay0/a;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;


# direct methods
.method public constructor <init>(Lt10/k;Lne/b;Ljava/lang/String;Lay0/a;)V
    .locals 0

    .line 1
    const-string p2, "profileUuid"

    .line 2
    .line 3
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p2, "dynamicRateRegistered"

    .line 7
    .line 8
    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lue/b;->d:Lt10/k;

    .line 15
    .line 16
    iput-object p4, p0, Lue/b;->e:Lay0/a;

    .line 17
    .line 18
    sget-object p1, Lue/a;->j:Lue/a;

    .line 19
    .line 20
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    iput-object p2, p0, Lue/b;->f:Lyy0/c2;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p3

    .line 30
    sget-object p4, Lyy0/u1;->a:Lyy0/w1;

    .line 31
    .line 32
    invoke-static {p2, p3, p4, p1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lue/b;->g:Lyy0/l1;

    .line 37
    .line 38
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance p2, Lrp0/a;

    .line 43
    .line 44
    const/16 p3, 0x16

    .line 45
    .line 46
    const/4 p4, 0x0

    .line 47
    invoke-direct {p2, p0, p4, p3}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    const/4 p0, 0x3

    .line 51
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 52
    .line 53
    .line 54
    return-void
.end method

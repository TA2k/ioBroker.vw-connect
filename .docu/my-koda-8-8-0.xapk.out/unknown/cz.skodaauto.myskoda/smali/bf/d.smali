.class public final Lbf/d;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lay0/a;

.field public final e:Lay0/a;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;


# direct methods
.method public constructor <init>(Lay0/a;Lay0/a;)V
    .locals 2

    .line 1
    const-string v0, "onIntermediarySeasonSuccess"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "goToSecondSeason"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lbf/d;->d:Lay0/a;

    .line 15
    .line 16
    iput-object p2, p0, Lbf/d;->e:Lay0/a;

    .line 17
    .line 18
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iput-object p1, p0, Lbf/d;->f:Lyy0/c2;

    .line 25
    .line 26
    new-instance p2, Lyy0/l1;

    .line 27
    .line 28
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 29
    .line 30
    .line 31
    iput-object p2, p0, Lbf/d;->g:Lyy0/l1;

    .line 32
    .line 33
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    new-instance p2, La50/a;

    .line 38
    .line 39
    const/16 v0, 0x9

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    invoke-direct {p2, p0, v1, v0}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x3

    .line 46
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 47
    .line 48
    .line 49
    return-void
.end method

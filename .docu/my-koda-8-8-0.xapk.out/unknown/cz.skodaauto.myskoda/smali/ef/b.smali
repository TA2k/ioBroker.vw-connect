.class public final Lef/b;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lay0/k;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>(Lqe/a;Ljava/util/List;Lay0/k;)V
    .locals 8

    .line 1
    const-string v0, "season"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "selectedDays"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "onNext"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p3, p0, Lef/b;->d:Lay0/k;

    .line 20
    .line 21
    sget-object v2, Lgf/a;->d:Lgf/a;

    .line 22
    .line 23
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 24
    .line 25
    .line 26
    move-result p3

    .line 27
    const/4 v0, 0x7

    .line 28
    if-ge p3, v0, :cond_0

    .line 29
    .line 30
    move-object p3, p2

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p3, 0x0

    .line 33
    :goto_0
    if-nez p3, :cond_1

    .line 34
    .line 35
    sget-object p3, Lmx0/s;->d:Lmx0/s;

    .line 36
    .line 37
    :cond_1
    move-object v6, p3

    .line 38
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    if-ne p2, v0, :cond_2

    .line 43
    .line 44
    const/4 p2, 0x1

    .line 45
    :goto_1
    move v7, p2

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/4 p2, 0x0

    .line 48
    goto :goto_1

    .line 49
    :goto_2
    new-instance v1, Lef/a;

    .line 50
    .line 51
    const/4 v3, 0x0

    .line 52
    const/4 v4, 0x0

    .line 53
    move-object v5, p1

    .line 54
    invoke-direct/range {v1 .. v7}, Lef/a;-><init>(Lgf/a;ZZLqe/a;Ljava/util/List;Z)V

    .line 55
    .line 56
    .line 57
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    new-instance p2, Lyy0/l1;

    .line 62
    .line 63
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 64
    .line 65
    .line 66
    iput-object p2, p0, Lef/b;->e:Lyy0/l1;

    .line 67
    .line 68
    return-void
.end method

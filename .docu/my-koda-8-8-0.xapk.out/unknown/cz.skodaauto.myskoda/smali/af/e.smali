.class public final Laf/e;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lle/a;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/util/List;Lle/a;)V
    .locals 1

    .line 1
    const-string v0, "selectedKolaDays"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Laf/e;->d:Lle/a;

    .line 10
    .line 11
    new-instance p2, Laf/d;

    .line 12
    .line 13
    move-object v0, p1

    .line 14
    check-cast v0, Ljava/util/Collection;

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    xor-int/lit8 v0, v0, 0x1

    .line 21
    .line 22
    invoke-direct {p2, v0, p1}, Laf/d;-><init>(ZLjava/util/List;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    new-instance p2, Lyy0/l1;

    .line 30
    .line 31
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 32
    .line 33
    .line 34
    iput-object p2, p0, Laf/e;->e:Lyy0/l1;

    .line 35
    .line 36
    return-void
.end method

.class public final Lng/g;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lxh/e;

.field public final e:Lac/i;

.field public final f:Lyy0/l1;


# direct methods
.method public constructor <init>(Lac/e;Lac/a0;ZLxh/e;)V
    .locals 7

    .line 1
    const-string v0, "userLegalCountry"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p4, p0, Lng/g;->d:Lxh/e;

    .line 10
    .line 11
    new-instance v1, Lac/i;

    .line 12
    .line 13
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 18
    .line 19
    move-object v5, p1

    .line 20
    move-object v3, p2

    .line 21
    move v4, p3

    .line 22
    invoke-direct/range {v1 .. v6}, Lac/i;-><init>(Lr7/a;Lac/a0;ZLac/e;Ljava/util/List;)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lng/g;->e:Lac/i;

    .line 26
    .line 27
    iget-object p1, v1, Lac/i;->l:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Lyy0/l1;

    .line 30
    .line 31
    new-instance p2, Lhg/q;

    .line 32
    .line 33
    const/16 p3, 0x11

    .line 34
    .line 35
    invoke-direct {p2, p1, p3}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance p3, Lng/e;

    .line 43
    .line 44
    sget-object p4, Lac/x;->v:Lac/x;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p3, p4, v0}, Lng/e;-><init>(Lac/x;Z)V

    .line 48
    .line 49
    .line 50
    sget-object p4, Lyy0/u1;->b:Lyy0/w1;

    .line 51
    .line 52
    invoke-static {p2, p1, p4, p3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    iput-object p1, p0, Lng/g;->f:Lyy0/l1;

    .line 57
    .line 58
    return-void
.end method

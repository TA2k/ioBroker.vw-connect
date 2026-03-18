.class public final Log/h;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lxh/e;

.field public final e:Ljava/util/List;

.field public final f:Lac/i;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;


# direct methods
.method public constructor <init>(Lac/e;Log/i;Lac/a0;Lxh/e;Ljava/util/List;)V
    .locals 7

    .line 1
    const-string v0, "userLegalCountry"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "availableShippingCountries"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p4, p0, Log/h;->d:Lxh/e;

    .line 15
    .line 16
    iput-object p5, p0, Log/h;->e:Ljava/util/List;

    .line 17
    .line 18
    new-instance v1, Lac/i;

    .line 19
    .line 20
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    const/4 v4, 0x0

    .line 25
    move-object v5, p1

    .line 26
    move-object v3, p3

    .line 27
    move-object v6, p5

    .line 28
    invoke-direct/range {v1 .. v6}, Lac/i;-><init>(Lr7/a;Lac/a0;ZLac/e;Ljava/util/List;)V

    .line 29
    .line 30
    .line 31
    iput-object v1, p0, Log/h;->f:Lac/i;

    .line 32
    .line 33
    if-nez p2, :cond_0

    .line 34
    .line 35
    sget-object p2, Log/i;->d:Log/i;

    .line 36
    .line 37
    :cond_0
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iput-object p1, p0, Log/h;->g:Lyy0/c2;

    .line 42
    .line 43
    iget-object p2, v1, Lac/i;->l:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p2, Lyy0/l1;

    .line 46
    .line 47
    new-instance p3, Lal0/y0;

    .line 48
    .line 49
    const/4 p4, 0x3

    .line 50
    const/16 p5, 0x10

    .line 51
    .line 52
    const/4 v0, 0x0

    .line 53
    invoke-direct {p3, p4, v0, p5}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    new-instance p4, Lbn0/f;

    .line 57
    .line 58
    const/4 p5, 0x5

    .line 59
    invoke-direct {p4, p2, p1, p3, p5}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    new-instance v0, Log/f;

    .line 67
    .line 68
    sget-object v1, Lac/x;->v:Lac/x;

    .line 69
    .line 70
    sget-object v2, Log/i;->d:Log/i;

    .line 71
    .line 72
    const/4 v4, 0x0

    .line 73
    const/4 v5, 0x0

    .line 74
    const/4 v3, 0x1

    .line 75
    invoke-direct/range {v0 .. v5}, Log/f;-><init>(Lac/x;Log/i;ZZZ)V

    .line 76
    .line 77
    .line 78
    sget-object p2, Lyy0/u1;->b:Lyy0/w1;

    .line 79
    .line 80
    invoke-static {p4, p1, p2, v0}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    iput-object p1, p0, Log/h;->h:Lyy0/l1;

    .line 85
    .line 86
    return-void
.end method

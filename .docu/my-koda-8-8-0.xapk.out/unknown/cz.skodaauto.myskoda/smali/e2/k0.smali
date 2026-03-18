.class public final Le2/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final a:Le2/k0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Le2/k0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le2/k0;->a:Le2/k0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 6

    .line 1
    new-instance p0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 8
    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Ljava/util/Collection;

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x0

    .line 18
    move v2, v1

    .line 19
    move v3, v2

    .line 20
    :goto_0
    if-ge v1, v0, :cond_0

    .line 21
    .line 22
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    check-cast v4, Lt3/p0;

    .line 27
    .line 28
    invoke-interface {v4, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    iget v5, v4, Lt3/e1;->d:I

    .line 33
    .line 34
    invoke-static {v2, v5}, Ljava/lang/Math;->max(II)I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    iget v5, v4, Lt3/e1;->e:I

    .line 39
    .line 40
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    add-int/lit8 v1, v1, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    new-instance p2, Le2/j0;

    .line 51
    .line 52
    const/4 p3, 0x0

    .line 53
    invoke-direct {p2, p0, p3}, Le2/j0;-><init>(Ljava/util/ArrayList;I)V

    .line 54
    .line 55
    .line 56
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 57
    .line 58
    invoke-interface {p1, v2, v3, p0, p2}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method

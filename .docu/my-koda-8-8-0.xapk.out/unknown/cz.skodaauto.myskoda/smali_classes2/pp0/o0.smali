.class public final Lpp0/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpp0/c0;


# direct methods
.method public constructor <init>(Lpp0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/o0;->a:Lpp0/c0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(I)V
    .locals 6

    .line 1
    iget-object p0, p0, Lpp0/o0;->a:Lpp0/c0;

    .line 2
    .line 3
    check-cast p0, Lnp0/b;

    .line 4
    .line 5
    iget-object p0, p0, Lnp0/b;->h:Lyy0/c2;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    move-object v1, v0

    .line 12
    check-cast v1, Lqp0/g;

    .line 13
    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    iget-object v2, v1, Lqp0/g;->a:Ljava/util/List;

    .line 17
    .line 18
    check-cast v2, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    new-instance v3, Lac/g;

    .line 25
    .line 26
    const/16 v4, 0xa

    .line 27
    .line 28
    invoke-direct {v3, p1, v4}, Lac/g;-><init>(II)V

    .line 29
    .line 30
    .line 31
    new-instance v4, Lac0/s;

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v4, v3, v5}, Lac0/s;-><init>(Ljava/lang/Object;I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->removeIf(Ljava/util/function/Predicate;)Z

    .line 38
    .line 39
    .line 40
    invoke-static {v2}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    iget-object v3, v1, Lqp0/g;->b:Ljava/lang/Integer;

    .line 45
    .line 46
    iget-boolean v1, v1, Lqp0/g;->c:Z

    .line 47
    .line 48
    new-instance v4, Lqp0/g;

    .line 49
    .line 50
    invoke-direct {v4, v2, v3, v1}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 51
    .line 52
    .line 53
    invoke-static {v4}, Ljp/bg;->e(Lqp0/g;)Lqp0/g;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    goto :goto_0

    .line 58
    :cond_1
    const/4 v1, 0x0

    .line 59
    :goto_0
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_0

    .line 64
    .line 65
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {p0, v1}, Lpp0/o0;->a(I)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

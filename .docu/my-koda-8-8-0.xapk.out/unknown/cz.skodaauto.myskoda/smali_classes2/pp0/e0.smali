.class public final Lpp0/e0;
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
    iput-object p1, p0, Lpp0/e0;->a:Lpp0/c0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Llx0/l;)V
    .locals 6

    .line 1
    iget-object v0, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p1, Ljava/lang/Number;

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iget-object p0, p0, Lpp0/e0;->a:Lpp0/c0;

    .line 18
    .line 19
    check-cast p0, Lnp0/b;

    .line 20
    .line 21
    iget-object p0, p0, Lnp0/b;->h:Lyy0/c2;

    .line 22
    .line 23
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    move-object v2, v1

    .line 28
    check-cast v2, Lqp0/g;

    .line 29
    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    iget-object v3, v2, Lqp0/g;->a:Ljava/util/List;

    .line 33
    .line 34
    check-cast v3, Ljava/util/Collection;

    .line 35
    .line 36
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    check-cast v4, Llx0/l;

    .line 45
    .line 46
    invoke-virtual {v3, p1, v4}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-static {v3}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    iget-object v4, v2, Lqp0/g;->b:Ljava/lang/Integer;

    .line 54
    .line 55
    iget-boolean v2, v2, Lqp0/g;->c:Z

    .line 56
    .line 57
    new-instance v5, Lqp0/g;

    .line 58
    .line 59
    invoke-direct {v5, v3, v4, v2}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    const/4 v5, 0x0

    .line 64
    :goto_0
    invoke-virtual {p0, v1, v5}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-eqz v1, :cond_0

    .line 69
    .line 70
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
    check-cast v1, Llx0/l;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lpp0/e0;->a(Llx0/l;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

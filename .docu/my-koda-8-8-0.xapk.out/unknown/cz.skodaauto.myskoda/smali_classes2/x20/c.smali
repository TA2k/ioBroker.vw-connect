.class public final Lx20/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkj0/b;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/util/Set;


# direct methods
.method public constructor <init>(Ljava/lang/String;I)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lx20/c;->a:I

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Llx0/l;

    const-string v1, "dealer_id"

    invoke-direct {v0, v1, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 3
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    .line 4
    new-instance p2, Llx0/l;

    const-string v1, "mileage"

    invoke-direct {p2, v1, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 5
    filled-new-array {v0, p2}, [Llx0/l;

    move-result-object p1

    .line 6
    invoke-static {p1}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p1

    .line 7
    iput-object p1, p0, Lx20/c;->b:Ljava/util/Set;

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/util/List;)V
    .locals 7

    const/4 v0, 0x0

    iput v0, p0, Lx20/c;->a:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    new-instance v0, Lnx0/i;

    invoke-direct {v0}, Lnx0/i;-><init>()V

    .line 10
    move-object v1, p1

    check-cast v1, Ljava/util/Collection;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    .line 11
    new-instance v2, Llx0/l;

    const-string v3, "delivered_vehicles"

    invoke-direct {v2, v3, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 12
    invoke-virtual {v0, v2}, Lnx0/i;->add(Ljava/lang/Object;)Z

    .line 13
    sget-object v1, Lss0/m;->n:Lsx0/b;

    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    new-instance v2, Landroidx/collection/d1;

    const/4 v3, 0x6

    invoke-direct {v2, v1, v3}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 16
    :goto_0
    invoke-virtual {v2}, Landroidx/collection/d1;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-virtual {v2}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lss0/m;

    .line 17
    invoke-static {v1}, Llp/nd;->b(Ljava/lang/Enum;)Ljava/lang/String;

    move-result-object v3

    move-object v4, p1

    check-cast v4, Ljava/lang/Iterable;

    .line 18
    instance-of v5, v4, Ljava/util/Collection;

    const/4 v6, 0x0

    if-eqz v5, :cond_0

    move-object v5, v4

    check-cast v5, Ljava/util/Collection;

    invoke-interface {v5}, Ljava/util/Collection;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_0

    goto :goto_2

    .line 19
    :cond_0
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_1
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lss0/k;

    .line 20
    iget-object v5, v5, Lss0/k;->d:Lss0/m;

    if-ne v5, v1, :cond_1

    add-int/lit8 v6, v6, 0x1

    if-ltz v6, :cond_2

    goto :goto_1

    .line 21
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    const/4 p0, 0x0

    throw p0

    .line 22
    :cond_3
    :goto_2
    invoke-static {v6}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    .line 23
    new-instance v4, Llx0/l;

    invoke-direct {v4, v3, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 24
    invoke-virtual {v0, v4}, Lnx0/i;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 25
    :cond_4
    check-cast p2, Ljava/util/Collection;

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p1

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    .line 26
    new-instance p2, Llx0/l;

    const-string v1, "ordered_vehicles"

    invoke-direct {p2, v1, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 27
    invoke-virtual {v0, p2}, Lnx0/i;->add(Ljava/lang/Object;)Z

    .line 28
    invoke-static {v0}, Ljp/m1;->c(Lnx0/i;)Lnx0/i;

    move-result-object p1

    iput-object p1, p0, Lx20/c;->b:Ljava/util/Set;

    return-void
.end method


# virtual methods
.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lx20/c;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "preferred_service_partner"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "garage_vehicles_states"

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getParams()Ljava/util/Set;
    .locals 1

    .line 1
    iget v0, p0, Lx20/c;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lx20/c;->b:Ljava/util/Set;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Lx20/c;->b:Ljava/util/Set;

    .line 10
    .line 11
    check-cast p0, Lnx0/i;

    .line 12
    .line 13
    return-object p0

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

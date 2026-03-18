.class public final Lmw/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/List;

.field public final b:I

.field public final c:Lrw/b;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lmw/a;

    .line 2
    .line 3
    sget-object v1, Lrw/b;->b:Lrw/b;

    .line 4
    .line 5
    sget-object v5, Lrw/b;->b:Lrw/b;

    .line 6
    .line 7
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const-wide/16 v3, 0x0

    .line 11
    .line 12
    invoke-direct/range {v0 .. v5}, Lmw/a;-><init>(Ljava/util/List;IDLrw/b;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Ljava/util/List;IDLrw/b;)V
    .locals 0

    const-string p3, "extraStore"

    invoke-static {p5, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    iput-object p1, p0, Lmw/a;->a:Ljava/util/List;

    .line 25
    iput p2, p0, Lmw/a;->b:I

    .line 26
    iput-object p5, p0, Lmw/a;->c:Lrw/b;

    return-void
.end method

.method public varargs constructor <init>([Lmw/j;)V
    .locals 10

    .line 1
    invoke-static {p1}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    .line 2
    sget-object v5, Lrw/b;->b:Lrw/b;

    .line 3
    const-string p1, "extraStore"

    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    move-object p1, v1

    check-cast p1, Ljava/lang/Iterable;

    .line 5
    new-instance v0, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {p1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 6
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    .line 7
    check-cast v3, Lmw/j;

    .line 8
    iget v3, v3, Lmw/j;->c:I

    .line 9
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    .line 10
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 11
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v2

    .line 12
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lmw/j;

    .line 13
    iget-wide v3, v3, Lmw/j;->e:D

    .line 14
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lmw/j;

    .line 15
    iget-wide v6, v6, Lmw/j;->e:D

    .line 16
    invoke-static {v3, v4, v6, v7}, Ljava/lang/Math;->max(DD)D

    move-result-wide v3

    goto :goto_1

    :cond_1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lmw/j;

    .line 17
    iget-wide v6, v0, Lmw/j;->d:D

    .line 18
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lmw/j;

    .line 19
    iget-wide v8, v0, Lmw/j;->d:D

    .line 20
    invoke-static {v6, v7, v8, v9}, Ljava/lang/Math;->min(DD)D

    move-result-wide v6

    goto :goto_2

    :cond_2
    sub-double/2addr v3, v6

    move-object v0, p0

    .line 21
    invoke-direct/range {v0 .. v5}, Lmw/a;-><init>(Ljava/util/List;IDLrw/b;)V

    return-void

    .line 22
    :cond_3
    new-instance p0, Ljava/util/NoSuchElementException;

    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    throw p0

    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    throw p0
.end method

.class public final Landroidx/collection/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/List;
.implements Lby0/c;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final add(ILjava/lang/Object;)V
    .locals 3

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 3
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Ln2/b;

    invoke-virtual {p0, p1, p2}, Ln2/b;->b(ILjava/lang/Object;)V

    return-void

    .line 4
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Landroidx/collection/l0;

    if-ltz p1, :cond_2

    .line 5
    iget v0, p0, Landroidx/collection/l0;->b:I

    if-gt p1, v0, :cond_2

    add-int/lit8 v0, v0, 0x1

    .line 6
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 7
    array-length v2, v1

    if-ge v2, v0, :cond_0

    .line 8
    invoke-virtual {p0, v0, v1}, Landroidx/collection/l0;->l(I[Ljava/lang/Object;)V

    .line 9
    :cond_0
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 10
    iget v1, p0, Landroidx/collection/l0;->b:I

    if-eq p1, v1, :cond_1

    add-int/lit8 v2, p1, 0x1

    .line 11
    invoke-static {v2, p1, v1, v0, v0}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 12
    :cond_1
    aput-object p2, v0, p1

    .line 13
    iget p1, p0, Landroidx/collection/l0;->b:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Landroidx/collection/l0;->b:I

    return-void

    .line 14
    :cond_2
    const-string p2, "Index "

    const-string v0, " must be in 0.."

    .line 15
    invoke-static {p2, p1, v0}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    .line 16
    iget p0, p0, Landroidx/collection/l0;->b:I

    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, La1/a;->d(Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 1

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Ln2/b;

    invoke-virtual {p0, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    :goto_0
    const/4 p0, 0x1

    return p0

    .line 2
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Landroidx/collection/l0;

    invoke-virtual {p0, p1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    goto :goto_0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 6

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Ln2/b;

    invoke-virtual {p0, p1, p2}, Ln2/b;->g(ILjava/util/Collection;)Z

    move-result p0

    return p0

    .line 2
    :pswitch_0
    const-string v0, "elements"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Landroidx/collection/l0;

    const/4 v0, 0x0

    if-ltz p1, :cond_5

    .line 4
    iget v1, p0, Landroidx/collection/l0;->b:I

    if-gt p1, v1, :cond_5

    .line 5
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    goto :goto_1

    .line 6
    :cond_0
    iget v1, p0, Landroidx/collection/l0;->b:I

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v3

    add-int/2addr v3, v1

    .line 7
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 8
    array-length v4, v1

    if-ge v4, v3, :cond_1

    .line 9
    invoke-virtual {p0, v3, v1}, Landroidx/collection/l0;->l(I[Ljava/lang/Object;)V

    .line 10
    :cond_1
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 11
    iget v3, p0, Landroidx/collection/l0;->b:I

    if-eq p1, v3, :cond_2

    .line 12
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v3

    add-int/2addr v3, p1

    .line 13
    iget v4, p0, Landroidx/collection/l0;->b:I

    .line 14
    invoke-static {v3, p1, v4, v1, v1}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 15
    :cond_2
    move-object v3, p2

    check-cast v3, Ljava/lang/Iterable;

    .line 16
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    add-int/lit8 v5, v2, 0x1

    if-ltz v2, :cond_3

    add-int/2addr v2, p1

    .line 17
    aput-object v4, v1, v2

    move v2, v5

    goto :goto_0

    .line 18
    :cond_3
    invoke-static {}, Ljp/k1;->r()V

    throw v0

    .line 19
    :cond_4
    iget p1, p0, Landroidx/collection/l0;->b:I

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p2

    add-int/2addr p2, p1

    iput p2, p0, Landroidx/collection/l0;->b:I

    const/4 v2, 0x1

    :goto_1
    return v2

    .line 20
    :cond_5
    const-string p2, "Index "

    const-string v1, " must be in 0.."

    .line 21
    invoke-static {p2, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    .line 22
    iget p0, p0, Landroidx/collection/l0;->b:I

    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, La1/a;->d(Ljava/lang/String;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 2

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 27
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Ln2/b;

    .line 28
    iget v0, p0, Ln2/b;->f:I

    .line 29
    invoke-virtual {p0, v0, p1}, Ln2/b;->g(ILjava/util/Collection;)Z

    move-result p0

    return p0

    .line 30
    :pswitch_0
    const-string v0, "elements"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Landroidx/collection/l0;

    check-cast p1, Ljava/lang/Iterable;

    .line 32
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 33
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    .line 34
    invoke-virtual {p0, v1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    goto :goto_0

    .line 35
    :cond_0
    iget p0, p0, Landroidx/collection/l0;->b:I

    if-eq v0, p0, :cond_1

    const/4 p0, 0x1

    goto :goto_1

    :cond_1
    const/4 p0, 0x0

    :goto_1
    return p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final clear()V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Landroidx/collection/l0;

    .line 17
    .line 18
    invoke-virtual {p0}, Landroidx/collection/l0;->c()V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Ln2/b;->j(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Landroidx/collection/l0;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->f(Ljava/lang/Object;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-ltz p0, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    :goto_0
    return p0

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    check-cast p1, Ljava/lang/Iterable;

    .line 14
    .line 15
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {p0, v0}, Ln2/b;->j(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    const/4 p0, 0x0

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const/4 p0, 0x1

    .line 38
    :goto_0
    return p0

    .line 39
    :pswitch_0
    const-string v0, "elements"

    .line 40
    .line 41
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Landroidx/collection/l0;

    .line 47
    .line 48
    check-cast p1, Ljava/lang/Iterable;

    .line 49
    .line 50
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {p0, v0}, Landroidx/collection/l0;->f(Ljava/lang/Object;)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-ltz v0, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    const/4 p0, 0x0

    .line 72
    goto :goto_2

    .line 73
    :cond_3
    const/4 p0, 0x1

    .line 74
    :goto_2
    return p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p0}, Ln2/c;->a(ILjava/util/List;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ln2/b;

    .line 12
    .line 13
    iget-object p0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    aget-object p0, p0, p1

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    invoke-static {p1, p0}, Landroidx/collection/w0;->a(ILjava/util/List;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroidx/collection/l0;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Ln2/b;->k(Ljava/lang/Object;)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Landroidx/collection/l0;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->f(Ljava/lang/Object;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final isEmpty()Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    iget p0, p0, Ln2/b;->f:I

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    :goto_0
    return p0

    .line 18
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroidx/collection/l0;

    .line 21
    .line 22
    invoke-virtual {p0}, Landroidx/collection/l0;->g()Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroidx/collection/i0;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x1

    .line 10
    invoke-direct {v0, v1, v2, p0}, Landroidx/collection/i0;-><init>(IILjava/util/List;)V

    .line 11
    .line 12
    .line 13
    return-object v0

    .line 14
    :pswitch_0
    new-instance v0, Landroidx/collection/i0;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v0, v1, v2, p0}, Landroidx/collection/i0;-><init>(IILjava/util/List;)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 3

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    iget v0, p0, Ln2/b;->f:I

    .line 11
    .line 12
    add-int/lit8 v0, v0, -0x1

    .line 13
    .line 14
    iget-object p0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 15
    .line 16
    :goto_0
    if-ltz v0, :cond_1

    .line 17
    .line 18
    aget-object v1, p0, v0

    .line 19
    .line 20
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 v0, -0x1

    .line 31
    :goto_1
    return v0

    .line 32
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Landroidx/collection/l0;

    .line 35
    .line 36
    const/4 v0, -0x1

    .line 37
    if-nez p1, :cond_3

    .line 38
    .line 39
    iget-object p1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 40
    .line 41
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 42
    .line 43
    add-int/lit8 p0, p0, -0x1

    .line 44
    .line 45
    :goto_2
    if-ge v0, p0, :cond_5

    .line 46
    .line 47
    aget-object v1, p1, p0

    .line 48
    .line 49
    if-nez v1, :cond_2

    .line 50
    .line 51
    :goto_3
    move v0, p0

    .line 52
    goto :goto_5

    .line 53
    :cond_2
    add-int/lit8 p0, p0, -0x1

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_3
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 57
    .line 58
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 59
    .line 60
    add-int/lit8 p0, p0, -0x1

    .line 61
    .line 62
    :goto_4
    if-ge v0, p0, :cond_5

    .line 63
    .line 64
    aget-object v2, v1, p0

    .line 65
    .line 66
    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    if-eqz v2, :cond_4

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    add-int/lit8 p0, p0, -0x1

    .line 74
    .line 75
    goto :goto_4

    .line 76
    :cond_5
    :goto_5
    return v0

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 3

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    new-instance v0, Landroidx/collection/i0;

    const/4 v1, 0x0

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2, p0}, Landroidx/collection/i0;-><init>(IILjava/util/List;)V

    return-object v0

    .line 2
    :pswitch_0
    new-instance v0, Landroidx/collection/i0;

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2, p0}, Landroidx/collection/i0;-><init>(IILjava/util/List;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 2

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 3
    new-instance v0, Landroidx/collection/i0;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1, p0}, Landroidx/collection/i0;-><init>(IILjava/util/List;)V

    return-object v0

    .line 4
    :pswitch_0
    new-instance v0, Landroidx/collection/i0;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1, p0}, Landroidx/collection/i0;-><init>(IILjava/util/List;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 3
    invoke-static {p1, p0}, Ln2/c;->a(ILjava/util/List;)V

    .line 4
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Ln2/b;

    invoke-virtual {p0, p1}, Ln2/b;->m(I)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    .line 5
    :pswitch_0
    invoke-static {p1, p0}, Landroidx/collection/w0;->a(ILjava/util/List;)V

    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Landroidx/collection/l0;

    invoke-virtual {p0, p1}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 1

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Ln2/b;

    invoke-virtual {p0, p1}, Ln2/b;->l(Ljava/lang/Object;)Z

    move-result p0

    return p0

    .line 2
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    check-cast p0, Landroidx/collection/l0;

    invoke-virtual {p0, p1}, Landroidx/collection/l0;->i(Ljava/lang/Object;)Z

    move-result p0

    return p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_0
    iget v0, p0, Ln2/b;->f:I

    .line 21
    .line 22
    check-cast p1, Ljava/lang/Iterable;

    .line 23
    .line 24
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {p0, v1}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    iget p0, p0, Ln2/b;->f:I

    .line 43
    .line 44
    if-eq v0, p0, :cond_2

    .line 45
    .line 46
    const/4 p0, 0x1

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    :goto_1
    const/4 p0, 0x0

    .line 49
    :goto_2
    return p0

    .line 50
    :pswitch_0
    const-string v0, "elements"

    .line 51
    .line 52
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Landroidx/collection/l0;

    .line 58
    .line 59
    check-cast p1, Ljava/lang/Iterable;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 65
    .line 66
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-eqz v1, :cond_3

    .line 75
    .line 76
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-virtual {p0, v1}, Landroidx/collection/l0;->i(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_3
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 85
    .line 86
    if-eq v0, p0, :cond_4

    .line 87
    .line 88
    const/4 p0, 0x1

    .line 89
    goto :goto_4

    .line 90
    :cond_4
    const/4 p0, 0x0

    .line 91
    :goto_4
    return p0

    .line 92
    nop

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 4

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    iget v0, p0, Ln2/b;->f:I

    .line 11
    .line 12
    add-int/lit8 v1, v0, -0x1

    .line 13
    .line 14
    :goto_0
    const/4 v2, -0x1

    .line 15
    if-ge v2, v1, :cond_1

    .line 16
    .line 17
    iget-object v2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 18
    .line 19
    aget-object v2, v2, v1

    .line 20
    .line 21
    invoke-interface {p1, v2}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-nez v2, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0, v1}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    :cond_0
    add-int/lit8 v1, v1, -0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    iget p0, p0, Ln2/b;->f:I

    .line 34
    .line 35
    if-eq v0, p0, :cond_2

    .line 36
    .line 37
    const/4 p0, 0x1

    .line 38
    goto :goto_1

    .line 39
    :cond_2
    const/4 p0, 0x0

    .line 40
    :goto_1
    return p0

    .line 41
    :pswitch_0
    const-string v0, "elements"

    .line 42
    .line 43
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Landroidx/collection/l0;

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 54
    .line 55
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 56
    .line 57
    add-int/lit8 v2, v0, -0x1

    .line 58
    .line 59
    :goto_2
    const/4 v3, -0x1

    .line 60
    if-ge v3, v2, :cond_4

    .line 61
    .line 62
    aget-object v3, v1, v2

    .line 63
    .line 64
    invoke-interface {p1, v3}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-nez v3, :cond_3

    .line 69
    .line 70
    invoke-virtual {p0, v2}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    :cond_3
    add-int/lit8 v2, v2, -0x1

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 77
    .line 78
    if-eq v0, p0, :cond_5

    .line 79
    .line 80
    const/4 p0, 0x1

    .line 81
    goto :goto_3

    .line 82
    :cond_5
    const/4 p0, 0x0

    .line 83
    :goto_3
    return p0

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p0}, Ln2/c;->a(ILjava/util/List;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ln2/b;

    .line 12
    .line 13
    iget-object p0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    aget-object v0, p0, p1

    .line 16
    .line 17
    aput-object p2, p0, p1

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    invoke-static {p1, p0}, Landroidx/collection/w0;->a(ILjava/util/List;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Landroidx/collection/l0;

    .line 26
    .line 27
    if-ltz p1, :cond_0

    .line 28
    .line 29
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 30
    .line 31
    if-ge p1, v0, :cond_0

    .line 32
    .line 33
    iget-object p0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 34
    .line 35
    aget-object v0, p0, p1

    .line 36
    .line 37
    aput-object p2, p0, p1

    .line 38
    .line 39
    return-object v0

    .line 40
    :cond_0
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->m(I)V

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x0

    .line 44
    throw p0

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln2/b;

    .line 9
    .line 10
    iget p0, p0, Ln2/b;->f:I

    .line 11
    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Landroidx/collection/l0;

    .line 16
    .line 17
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 18
    .line 19
    return p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final subList(II)Ljava/util/List;
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p2, p0}, Ln2/c;->b(IILjava/util/List;)V

    .line 7
    .line 8
    .line 9
    new-instance v0, Landroidx/collection/k0;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, p0, p1, p2, v1}, Landroidx/collection/k0;-><init>(Ljava/util/List;III)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    invoke-static {p1, p2, p0}, Landroidx/collection/w0;->b(IILjava/util/List;)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Landroidx/collection/k0;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p1, p2, v1}, Landroidx/collection/k0;-><init>(Ljava/util/List;III)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final toArray()[Ljava/lang/Object;
    .locals 1

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/l;->a(Ljava/util/Collection;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0

    .line 2
    :pswitch_0
    invoke-static {p0}, Lkotlin/jvm/internal/l;->a(Ljava/util/Collection;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final toArray([Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 1

    iget v0, p0, Landroidx/collection/j0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 3
    invoke-static {p0, p1}, Lkotlin/jvm/internal/l;->b(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0

    .line 4
    :pswitch_0
    const-string v0, "array"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Lkotlin/jvm/internal/l;->b(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

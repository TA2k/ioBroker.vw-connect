.class public final Landroidx/collection/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/List;
.implements Lby0/c;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public final f:I

.field public g:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;III)V
    .locals 0

    .line 1
    iput p4, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput p2, p0, Landroidx/collection/k0;->f:I

    .line 6
    .line 7
    iput p3, p0, Landroidx/collection/k0;->g:I

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final add(ILjava/lang/Object;)V
    .locals 1

    iget v0, p0, Landroidx/collection/k0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 3
    iget v0, p0, Landroidx/collection/k0;->f:I

    add-int/2addr p1, v0

    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v0, p1, p2}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 4
    iget p1, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Landroidx/collection/k0;->g:I

    return-void

    .line 5
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->f:I

    add-int/2addr p1, v0

    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v0, p1, p2}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 6
    iget p1, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Landroidx/collection/k0;->g:I

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 2

    iget v0, p0, Landroidx/collection/k0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget v0, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 v1, v0, 0x1

    iput v1, p0, Landroidx/collection/k0;->g:I

    iget-object p0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {p0, v0, p1}, Ljava/util/List;->add(ILjava/lang/Object;)V

    :goto_0
    const/4 p0, 0x1

    return p0

    .line 2
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 v1, v0, 0x1

    iput v1, p0, Landroidx/collection/k0;->g:I

    iget-object p0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {p0, v0, p1}, Ljava/util/List;->add(ILjava/lang/Object;)V

    goto :goto_0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 1

    iget v0, p0, Landroidx/collection/k0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget v0, p0, Landroidx/collection/k0;->f:I

    add-int/2addr p1, v0

    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v0, p1, p2}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    .line 2
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p1

    .line 3
    iget p2, p0, Landroidx/collection/k0;->g:I

    add-int/2addr p2, p1

    iput p2, p0, Landroidx/collection/k0;->g:I

    if-lez p1, :cond_0

    const/4 p0, 0x1

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    return p0

    .line 4
    :pswitch_0
    const-string v0, "elements"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    iget v0, p0, Landroidx/collection/k0;->f:I

    add-int/2addr p1, v0

    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v0, p1, p2}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    .line 6
    iget p1, p0, Landroidx/collection/k0;->g:I

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v0

    add-int/2addr v0, p1

    iput v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p0

    if-lez p0, :cond_1

    const/4 p0, 0x1

    goto :goto_1

    :cond_1
    const/4 p0, 0x0

    :goto_1
    return p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 2

    iget v0, p0, Landroidx/collection/k0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 8
    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    iget v1, p0, Landroidx/collection/k0;->g:I

    invoke-interface {v0, v1, p1}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    .line 9
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result p1

    .line 10
    iget v0, p0, Landroidx/collection/k0;->g:I

    add-int/2addr v0, p1

    iput v0, p0, Landroidx/collection/k0;->g:I

    if-lez p1, :cond_0

    const/4 p0, 0x1

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    return p0

    .line 11
    :pswitch_0
    const-string v0, "elements"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    iget v1, p0, Landroidx/collection/k0;->g:I

    invoke-interface {v0, v1, p1}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    .line 13
    iget v0, p0, Landroidx/collection/k0;->g:I

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Landroidx/collection/k0;->g:I

    .line 14
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result p0

    if-lez p0, :cond_1

    const/4 p0, 0x1

    goto :goto_1

    :cond_1
    const/4 p0, 0x0

    :goto_1
    return p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final clear()V
    .locals 3

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    add-int/lit8 v0, v0, -0x1

    .line 9
    .line 10
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 11
    .line 12
    if-gt v1, v0, :cond_0

    .line 13
    .line 14
    :goto_0
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-interface {v2, v0}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    add-int/lit8 v0, v0, -0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iput v1, p0, Landroidx/collection/k0;->g:I

    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 28
    .line 29
    add-int/lit8 v0, v0, -0x1

    .line 30
    .line 31
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 32
    .line 33
    if-gt v1, v0, :cond_1

    .line 34
    .line 35
    :goto_1
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-interface {v2, v0}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    if-eq v0, v1, :cond_1

    .line 41
    .line 42
    add-int/lit8 v0, v0, -0x1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    iput v1, p0, Landroidx/collection/k0;->g:I

    .line 46
    .line 47
    return-void

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 9
    .line 10
    :goto_0
    if-ge v1, v0, :cond_1

    .line 11
    .line 12
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 13
    .line 14
    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    const/4 p0, 0x1

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 p0, 0x0

    .line 30
    :goto_1
    return p0

    .line 31
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 32
    .line 33
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 34
    .line 35
    :goto_2
    if-ge v1, v0, :cond_3

    .line 36
    .line 37
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 38
    .line 39
    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_2

    .line 48
    .line 49
    const/4 p0, 0x1

    .line 50
    goto :goto_3

    .line 51
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_3
    const/4 p0, 0x0

    .line 55
    :goto_3
    return p0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Iterable;

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {p0, v0}, Landroidx/collection/k0;->contains(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 p0, 0x1

    .line 31
    :goto_0
    return p0

    .line 32
    :pswitch_0
    const-string v0, "elements"

    .line 33
    .line 34
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    check-cast p1, Ljava/lang/Iterable;

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    :cond_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_3

    .line 48
    .line 49
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-virtual {p0, v0}, Landroidx/collection/k0;->contains(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-nez v0, :cond_2

    .line 58
    .line 59
    const/4 p0, 0x0

    .line 60
    goto :goto_1

    .line 61
    :cond_3
    const/4 p0, 0x1

    .line 62
    :goto_1
    return p0

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

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
    iget v0, p0, Landroidx/collection/k0;->f:I

    .line 10
    .line 11
    add-int/2addr p1, v0

    .line 12
    iget-object p0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 13
    .line 14
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    invoke-static {p1, p0}, Landroidx/collection/w0;->a(ILjava/util/List;)V

    .line 20
    .line 21
    .line 22
    iget v0, p0, Landroidx/collection/k0;->f:I

    .line 23
    .line 24
    add-int/2addr p1, v0

    .line 25
    iget-object p0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 4

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 9
    .line 10
    move v2, v1

    .line 11
    :goto_0
    if-ge v2, v0, :cond_1

    .line 12
    .line 13
    iget-object v3, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    sub-int/2addr v2, v1

    .line 26
    goto :goto_1

    .line 27
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 v2, -0x1

    .line 31
    :goto_1
    return v2

    .line 32
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 33
    .line 34
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 35
    .line 36
    move v2, v1

    .line 37
    :goto_2
    if-ge v2, v0, :cond_3

    .line 38
    .line 39
    iget-object v3, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    if-eqz v3, :cond_2

    .line 50
    .line 51
    sub-int/2addr v2, v1

    .line 52
    goto :goto_3

    .line 53
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_3
    const/4 v2, -0x1

    .line 57
    :goto_3
    return v2

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final isEmpty()Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    iget p0, p0, Landroidx/collection/k0;->f:I

    .line 9
    .line 10
    if-ne v0, p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    return p0

    .line 16
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 17
    .line 18
    iget p0, p0, Landroidx/collection/k0;->f:I

    .line 19
    .line 20
    if-ne v0, p0, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    const/4 p0, 0x0

    .line 25
    :goto_1
    return p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

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
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    add-int/lit8 v0, v0, -0x1

    .line 9
    .line 10
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 11
    .line 12
    if-gt v1, v0, :cond_1

    .line 13
    .line 14
    :goto_0
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    sub-int/2addr v0, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    if-eq v0, v1, :cond_1

    .line 29
    .line 30
    add-int/lit8 v0, v0, -0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 v0, -0x1

    .line 34
    :goto_1
    return v0

    .line 35
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 36
    .line 37
    add-int/lit8 v0, v0, -0x1

    .line 38
    .line 39
    iget v1, p0, Landroidx/collection/k0;->f:I

    .line 40
    .line 41
    if-gt v1, v0, :cond_3

    .line 42
    .line 43
    :goto_2
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 44
    .line 45
    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-eqz v2, :cond_2

    .line 54
    .line 55
    sub-int/2addr v0, v1

    .line 56
    goto :goto_3

    .line 57
    :cond_2
    if-eq v0, v1, :cond_3

    .line 58
    .line 59
    add-int/lit8 v0, v0, -0x1

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    const/4 v0, -0x1

    .line 63
    :goto_3
    return v0

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 3

    iget v0, p0, Landroidx/collection/k0;->d:I

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

    iget v0, p0, Landroidx/collection/k0;->d:I

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

    iget v0, p0, Landroidx/collection/k0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 9
    invoke-static {p1, p0}, Ln2/c;->a(ILjava/util/List;)V

    .line 10
    iget v0, p0, Landroidx/collection/k0;->f:I

    add-int/2addr p1, v0

    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v0, p1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    move-result-object p1

    .line 11
    iget v0, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Landroidx/collection/k0;->g:I

    return-object p1

    .line 12
    :pswitch_0
    invoke-static {p1, p0}, Landroidx/collection/w0;->a(ILjava/util/List;)V

    .line 13
    iget v0, p0, Landroidx/collection/k0;->f:I

    add-int/2addr p1, v0

    iget-object v0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v0, p1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    move-result-object p1

    .line 14
    iget v0, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Landroidx/collection/k0;->g:I

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 4

    iget v0, p0, Landroidx/collection/k0;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget v0, p0, Landroidx/collection/k0;->g:I

    iget v1, p0, Landroidx/collection/k0;->f:I

    :goto_0
    if-ge v1, v0, :cond_1

    .line 2
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    .line 3
    invoke-interface {v2, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 4
    iget p1, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 p1, p1, -0x1

    iput p1, p0, Landroidx/collection/k0;->g:I

    const/4 p0, 0x1

    goto :goto_1

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    :goto_1
    return p0

    .line 5
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    iget v1, p0, Landroidx/collection/k0;->f:I

    :goto_2
    if-ge v1, v0, :cond_3

    .line 6
    iget-object v2, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    .line 7
    invoke-interface {v2, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 8
    iget p1, p0, Landroidx/collection/k0;->g:I

    add-int/lit8 p1, p1, -0x1

    iput p1, p0, Landroidx/collection/k0;->g:I

    const/4 p0, 0x1

    goto :goto_3

    :cond_2
    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    :cond_3
    const/4 p0, 0x0

    :goto_3
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
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    check-cast p1, Ljava/lang/Iterable;

    .line 9
    .line 10
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {p0, v1}, Landroidx/collection/k0;->remove(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    iget p0, p0, Landroidx/collection/k0;->g:I

    .line 29
    .line 30
    if-eq v0, p0, :cond_1

    .line 31
    .line 32
    const/4 p0, 0x1

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const/4 p0, 0x0

    .line 35
    :goto_1
    return p0

    .line 36
    :pswitch_0
    const-string v0, "elements"

    .line 37
    .line 38
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 42
    .line 43
    check-cast p1, Ljava/lang/Iterable;

    .line 44
    .line 45
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_2

    .line 54
    .line 55
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {p0, v1}, Landroidx/collection/k0;->remove(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    iget p0, p0, Landroidx/collection/k0;->g:I

    .line 64
    .line 65
    if-eq v0, p0, :cond_3

    .line 66
    .line 67
    const/4 p0, 0x1

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    const/4 p0, 0x0

    .line 70
    :goto_3
    return p0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 5

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    add-int/lit8 v1, v0, -0x1

    .line 9
    .line 10
    iget v2, p0, Landroidx/collection/k0;->f:I

    .line 11
    .line 12
    if-gt v2, v1, :cond_1

    .line 13
    .line 14
    :goto_0
    iget-object v3, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-interface {p1, v4}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-nez v4, :cond_0

    .line 25
    .line 26
    invoke-interface {v3, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    iget v3, p0, Landroidx/collection/k0;->g:I

    .line 30
    .line 31
    add-int/lit8 v3, v3, -0x1

    .line 32
    .line 33
    iput v3, p0, Landroidx/collection/k0;->g:I

    .line 34
    .line 35
    :cond_0
    if-eq v1, v2, :cond_1

    .line 36
    .line 37
    add-int/lit8 v1, v1, -0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    iget p0, p0, Landroidx/collection/k0;->g:I

    .line 41
    .line 42
    if-eq v0, p0, :cond_2

    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    goto :goto_1

    .line 46
    :cond_2
    const/4 p0, 0x0

    .line 47
    :goto_1
    return p0

    .line 48
    :pswitch_0
    const-string v0, "elements"

    .line 49
    .line 50
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 54
    .line 55
    add-int/lit8 v1, v0, -0x1

    .line 56
    .line 57
    iget v2, p0, Landroidx/collection/k0;->f:I

    .line 58
    .line 59
    if-gt v2, v1, :cond_4

    .line 60
    .line 61
    :goto_2
    iget-object v3, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 62
    .line 63
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    invoke-interface {p1, v4}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-nez v4, :cond_3

    .line 72
    .line 73
    invoke-interface {v3, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    iget v3, p0, Landroidx/collection/k0;->g:I

    .line 77
    .line 78
    add-int/lit8 v3, v3, -0x1

    .line 79
    .line 80
    iput v3, p0, Landroidx/collection/k0;->g:I

    .line 81
    .line 82
    :cond_3
    if-eq v1, v2, :cond_4

    .line 83
    .line 84
    add-int/lit8 v1, v1, -0x1

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_4
    iget p0, p0, Landroidx/collection/k0;->g:I

    .line 88
    .line 89
    if-eq v0, p0, :cond_5

    .line 90
    .line 91
    const/4 p0, 0x1

    .line 92
    goto :goto_3

    .line 93
    :cond_5
    const/4 p0, 0x0

    .line 94
    :goto_3
    return p0

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

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
    iget v0, p0, Landroidx/collection/k0;->f:I

    .line 10
    .line 11
    add-int/2addr p1, v0

    .line 12
    iget-object p0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 13
    .line 14
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    invoke-static {p1, p0}, Landroidx/collection/w0;->a(ILjava/util/List;)V

    .line 20
    .line 21
    .line 22
    iget v0, p0, Landroidx/collection/k0;->f:I

    .line 23
    .line 24
    add-int/2addr p1, v0

    .line 25
    iget-object p0, p0, Landroidx/collection/k0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 7
    .line 8
    iget p0, p0, Landroidx/collection/k0;->f:I

    .line 9
    .line 10
    :goto_0
    sub-int/2addr v0, p0

    .line 11
    return v0

    .line 12
    :pswitch_0
    iget v0, p0, Landroidx/collection/k0;->g:I

    .line 13
    .line 14
    iget p0, p0, Landroidx/collection/k0;->f:I

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final subList(II)Ljava/util/List;
    .locals 2

    .line 1
    iget v0, p0, Landroidx/collection/k0;->d:I

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

    iget v0, p0, Landroidx/collection/k0;->d:I

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

    iget v0, p0, Landroidx/collection/k0;->d:I

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

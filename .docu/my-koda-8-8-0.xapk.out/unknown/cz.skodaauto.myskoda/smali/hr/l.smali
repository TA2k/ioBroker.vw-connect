.class public Lhr/l;
.super Ljava/util/AbstractCollection;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/List;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public f:Ljava/util/Collection;

.field public final g:Ljava/util/Collection;

.field public final h:Ljava/util/AbstractCollection;

.field public final synthetic i:Ljava/io/Serializable;

.field public final synthetic j:Ljava/io/Serializable;


# direct methods
.method public constructor <init>(Lhr/t0;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lhr/l;->d:I

    .line 5
    iput-object p1, p0, Lhr/l;->j:Ljava/io/Serializable;

    .line 6
    iput-object p1, p0, Lhr/l;->i:Ljava/io/Serializable;

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    .line 7
    iput-object p2, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 8
    iput-object p3, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 9
    iput-object p4, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    if-nez p4, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    .line 10
    :cond_0
    iget-object p1, p4, Lhr/l;->f:Ljava/util/Collection;

    .line 11
    :goto_0
    iput-object p1, p0, Lhr/l;->g:Ljava/util/Collection;

    return-void
.end method

.method public constructor <init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lhr/l;->d:I

    .line 1
    iput-object p1, p0, Lhr/l;->j:Ljava/io/Serializable;

    .line 2
    iput-object p1, p0, Lhr/l;->i:Ljava/io/Serializable;

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    iput-object p2, p0, Lhr/l;->e:Ljava/lang/Object;

    iput-object p3, p0, Lhr/l;->f:Ljava/util/Collection;

    iput-object p4, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    if-nez p4, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    iget-object p1, p4, Lhr/l;->f:Ljava/util/Collection;

    :goto_0
    iput-object p1, p0, Lhr/l;->g:Ljava/util/Collection;

    return-void
.end method

.method public constructor <init>(Llp/f;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lhr/l;->d:I

    .line 3
    iput-object p1, p0, Lhr/l;->j:Ljava/io/Serializable;

    .line 4
    iput-object p1, p0, Lhr/l;->i:Ljava/io/Serializable;

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    iput-object p2, p0, Lhr/l;->e:Ljava/lang/Object;

    iput-object p3, p0, Lhr/l;->f:Ljava/util/Collection;

    iput-object p4, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    if-nez p4, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    iget-object p1, p4, Lhr/l;->f:Ljava/util/Collection;

    :goto_0
    iput-object p1, p0, Lhr/l;->g:Ljava/util/Collection;

    return-void
.end method


# virtual methods
.method public final add(ILjava/lang/Object;)V
    .locals 2

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 2
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 3
    check-cast v1, Ljava/util/List;

    .line 4
    invoke-interface {v1, p1, p2}, Ljava/util/List;->add(ILjava/lang/Object;)V

    if-eqz v0, :cond_0

    .line 5
    invoke-virtual {p0}, Lhr/l;->i()V

    :cond_0
    return-void

    .line 6
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 7
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 8
    check-cast v1, Ljava/util/List;

    .line 9
    invoke-interface {v1, p1, p2}, Ljava/util/List;->add(ILjava/lang/Object;)V

    if-eqz v0, :cond_1

    .line 10
    invoke-virtual {p0}, Lhr/l;->i()V

    :cond_1
    return-void

    .line 11
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 12
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 13
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    .line 14
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 15
    check-cast v1, Ljava/util/List;

    .line 16
    invoke-interface {v1, p1, p2}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 17
    iget-object p1, p0, Lhr/l;->j:Ljava/io/Serializable;

    check-cast p1, Lhr/t0;

    .line 18
    iget p2, p1, Lhr/t0;->h:I

    add-int/lit8 p2, p2, 0x1

    iput p2, p1, Lhr/t0;->h:I

    if-eqz v0, :cond_2

    .line 19
    invoke-virtual {p0}, Lhr/l;->c()V

    :cond_2
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 3

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 20
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 21
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 22
    invoke-interface {v1, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    if-eqz v0, :cond_0

    .line 23
    invoke-virtual {p0}, Lhr/l;->i()V

    const/4 p1, 0x1

    :cond_0
    return p1

    .line 24
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 25
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 26
    invoke-interface {v1, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    if-eqz v0, :cond_1

    .line 27
    invoke-virtual {p0}, Lhr/l;->i()V

    const/4 p1, 0x1

    :cond_1
    return p1

    .line 28
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 29
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    .line 30
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    invoke-interface {v1, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    .line 31
    iget-object v1, p0, Lhr/l;->i:Ljava/io/Serializable;

    check-cast v1, Lhr/t0;

    .line 32
    iget v2, v1, Lhr/t0;->h:I

    add-int/lit8 v2, v2, 0x1

    iput v2, v1, Lhr/t0;->h:I

    if-eqz v0, :cond_2

    .line 33
    invoke-virtual {p0}, Lhr/l;->c()V

    :cond_2
    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 3

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x0

    goto :goto_0

    .line 2
    :cond_0
    invoke-virtual {p0}, Lhr/l;->size()I

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 3
    check-cast v1, Ljava/util/List;

    .line 4
    invoke-interface {v1, p1, p2}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p2, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 5
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    if-nez v0, :cond_1

    .line 6
    invoke-virtual {p0}, Lhr/l;->i()V

    const/4 p0, 0x1

    goto :goto_0

    :cond_1
    move p0, p1

    :goto_0
    return p0

    .line 7
    :pswitch_0
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2

    const/4 p0, 0x0

    goto :goto_1

    .line 8
    :cond_2
    invoke-virtual {p0}, Lhr/l;->size()I

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 9
    check-cast v1, Ljava/util/List;

    .line 10
    invoke-interface {v1, p1, p2}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_3

    iget-object p2, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 11
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    if-nez v0, :cond_3

    .line 12
    invoke-virtual {p0}, Lhr/l;->i()V

    const/4 p0, 0x1

    goto :goto_1

    :cond_3
    move p0, p1

    :goto_1
    return p0

    .line 13
    :pswitch_1
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_4

    const/4 p0, 0x0

    goto :goto_2

    .line 14
    :cond_4
    invoke-virtual {p0}, Lhr/l;->size()I

    move-result v0

    .line 15
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 16
    check-cast v1, Ljava/util/List;

    .line 17
    invoke-interface {v1, p1, p2}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_5

    .line 18
    iget-object p2, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 19
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p2

    .line 20
    iget-object v1, p0, Lhr/l;->j:Ljava/io/Serializable;

    check-cast v1, Lhr/t0;

    sub-int/2addr p2, v0

    .line 21
    iget v2, v1, Lhr/t0;->h:I

    add-int/2addr v2, p2

    iput v2, v1, Lhr/t0;->h:I

    if-nez v0, :cond_5

    .line 22
    invoke-virtual {p0}, Lhr/l;->c()V

    :cond_5
    move p0, p1

    :goto_2
    return p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 4

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 23
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x0

    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p0}, Lhr/l;->size()I

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 25
    invoke-interface {v1, p1}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 26
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    if-nez v0, :cond_1

    .line 27
    invoke-virtual {p0}, Lhr/l;->i()V

    const/4 p0, 0x1

    goto :goto_0

    :cond_1
    move p0, p1

    :goto_0
    return p0

    .line 28
    :pswitch_0
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2

    const/4 p0, 0x0

    goto :goto_1

    .line 29
    :cond_2
    invoke-virtual {p0}, Lhr/l;->size()I

    move-result v0

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 30
    invoke-interface {v1, p1}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_3

    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 31
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    if-nez v0, :cond_3

    .line 32
    invoke-virtual {p0}, Lhr/l;->i()V

    const/4 p0, 0x1

    goto :goto_1

    :cond_3
    move p0, p1

    :goto_1
    return p0

    .line 33
    :pswitch_1
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_4

    const/4 p0, 0x0

    goto :goto_2

    .line 34
    :cond_4
    invoke-virtual {p0}, Lhr/l;->size()I

    move-result v0

    .line 35
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    invoke-interface {v1, p1}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_5

    .line 36
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v1

    .line 37
    iget-object v2, p0, Lhr/l;->i:Ljava/io/Serializable;

    check-cast v2, Lhr/t0;

    sub-int/2addr v1, v0

    .line 38
    iget v3, v2, Lhr/t0;->h:I

    add-int/2addr v3, v1

    iput v3, v2, Lhr/t0;->h:I

    if-nez v0, :cond_5

    .line 39
    invoke-virtual {p0}, Lhr/l;->c()V

    :cond_5
    move p0, p1

    :goto_2
    return p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 2
    .line 3
    check-cast v0, Lhr/l;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lhr/l;->c()V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 12
    .line 13
    check-cast v0, Lhr/t0;

    .line 14
    .line 15
    iget-object v0, v0, Lhr/t0;->g:Ljava/util/Map;

    .line 16
    .line 17
    iget-object v1, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 20
    .line 21
    invoke-interface {v0, v1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final clear()V
    .locals 3

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Collection;->clear()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Lhr/l;->k()V

    .line 19
    .line 20
    .line 21
    :goto_0
    return-void

    .line 22
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Collection;->clear()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lhr/l;->k()V

    .line 35
    .line 36
    .line 37
    :goto_1
    return-void

    .line 38
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-nez v0, :cond_2

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 46
    .line 47
    invoke-interface {v1}, Ljava/util/Collection;->clear()V

    .line 48
    .line 49
    .line 50
    iget-object v1, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 51
    .line 52
    check-cast v1, Lhr/t0;

    .line 53
    .line 54
    iget v2, v1, Lhr/t0;->h:I

    .line 55
    .line 56
    sub-int/2addr v2, v0

    .line 57
    iput v2, v1, Lhr/t0;->h:I

    .line 58
    .line 59
    invoke-virtual {p0}, Lhr/l;->g()V

    .line 60
    .line 61
    .line 62
    :goto_2
    return-void

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 20
    .line 21
    invoke-interface {p0, p1}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 30
    .line 31
    invoke-interface {p0, p1}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ljava/util/Collection;->containsAll(Ljava/util/Collection;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 20
    .line 21
    invoke-interface {p0, p1}, Ljava/util/Collection;->containsAll(Ljava/util/Collection;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 30
    .line 31
    invoke-interface {p0, p1}, Ljava/util/Collection;->containsAll(Ljava/util/Collection;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public e()V
    .locals 2

    .line 1
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 2
    .line 3
    check-cast v0, Lhr/l;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {v0}, Lhr/l;->e()V

    .line 8
    .line 9
    .line 10
    iget-object v0, v0, Lhr/l;->f:Ljava/util/Collection;

    .line 11
    .line 12
    iget-object p0, p0, Lhr/l;->g:Ljava/util/Collection;

    .line 13
    .line 14
    if-ne v0, p0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 32
    .line 33
    check-cast v0, Lhr/t0;

    .line 34
    .line 35
    iget-object v0, v0, Lhr/t0;->g:Ljava/util/Map;

    .line 36
    .line 37
    iget-object v1, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 38
    .line 39
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Ljava/util/Collection;

    .line 44
    .line 45
    if-eqz v0, :cond_2

    .line 46
    .line 47
    iput-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 48
    .line 49
    :cond_2
    :goto_0
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    if-ne p1, p0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    :goto_0
    return p0

    .line 20
    :pswitch_0
    if-ne p1, p0, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    :goto_1
    return p0

    .line 34
    :pswitch_1
    if-ne p1, p0, :cond_2

    .line 35
    .line 36
    const/4 p0, 0x1

    .line 37
    goto :goto_2

    .line 38
    :cond_2
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 42
    .line 43
    invoke-interface {p0, p1}, Ljava/util/Collection;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    :goto_2
    return p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public g()V
    .locals 1

    .line 1
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 2
    .line 3
    check-cast v0, Lhr/l;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lhr/l;->g()V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 20
    .line 21
    check-cast v0, Lhr/t0;

    .line 22
    .line 23
    iget-object v0, v0, Lhr/t0;->g:Ljava/util/Map;

    .line 24
    .line 25
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 26
    .line 27
    invoke-interface {v0, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    :cond_1
    return-void
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    check-cast p0, Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 22
    .line 23
    check-cast p0, Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 34
    .line 35
    check-cast p0, Ljava/util/List;

    .line 36
    .line 37
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Collection;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public i()V
    .locals 2

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 7
    .line 8
    check-cast v0, Lhr/l;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Lhr/l;->i()V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 17
    .line 18
    check-cast v0, Llp/f;

    .line 19
    .line 20
    iget-object v0, v0, Llp/f;->f:Llp/j;

    .line 21
    .line 22
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 23
    .line 24
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 25
    .line 26
    invoke-virtual {v0, p0, v1}, Llp/j;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    :goto_0
    return-void

    .line 30
    :pswitch_0
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 31
    .line 32
    check-cast v0, Lhr/l;

    .line 33
    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    invoke-virtual {v0}, Lhr/l;->i()V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 41
    .line 42
    check-cast v0, Ljp/o;

    .line 43
    .line 44
    iget-object v0, v0, Ljp/o;->f:Ljp/t;

    .line 45
    .line 46
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 47
    .line 48
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 49
    .line 50
    invoke-virtual {v0, p0, v1}, Ljp/t;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    :goto_1
    return-void

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    check-cast p0, Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 22
    .line 23
    check-cast p0, Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0

    .line 30
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 34
    .line 35
    check-cast p0, Ljava/util/List;

    .line 36
    .line 37
    invoke-interface {p0, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    return p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    new-instance v0, Llp/b;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Llp/b;-><init>(Lhr/l;)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 16
    .line 17
    .line 18
    new-instance v0, Ljp/i;

    .line 19
    .line 20
    invoke-direct {v0, p0}, Ljp/i;-><init>(Lhr/l;)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lhr/c;

    .line 28
    .line 29
    invoke-direct {v0, p0}, Lhr/c;-><init>(Lhr/l;)V

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public k()V
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 7
    .line 8
    check-cast v0, Lhr/l;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Lhr/l;->k()V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 25
    .line 26
    check-cast v0, Llp/f;

    .line 27
    .line 28
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 29
    .line 30
    iget-object v0, v0, Llp/f;->f:Llp/j;

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Llp/j;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void

    .line 36
    :pswitch_0
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 37
    .line 38
    check-cast v0, Lhr/l;

    .line 39
    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    invoke-virtual {v0}, Lhr/l;->k()V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 47
    .line 48
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 55
    .line 56
    check-cast v0, Ljp/o;

    .line 57
    .line 58
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 59
    .line 60
    iget-object v0, v0, Ljp/o;->f:Ljp/t;

    .line 61
    .line 62
    invoke-virtual {v0, p0}, Ljp/t;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    :cond_3
    :goto_1
    return-void

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public l()V
    .locals 2

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 7
    .line 8
    check-cast v0, Lhr/l;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-virtual {v0}, Lhr/l;->l()V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lhr/l;->g:Ljava/util/Collection;

    .line 16
    .line 17
    iget-object v0, v0, Lhr/l;->f:Ljava/util/Collection;

    .line 18
    .line 19
    if-ne v0, p0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 29
    .line 30
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 37
    .line 38
    check-cast v0, Llp/f;

    .line 39
    .line 40
    iget-object v1, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 41
    .line 42
    iget-object v0, v0, Llp/f;->f:Llp/j;

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Llp/j;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Ljava/util/Collection;

    .line 49
    .line 50
    if-eqz v0, :cond_2

    .line 51
    .line 52
    iput-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 53
    .line 54
    :cond_2
    :goto_0
    return-void

    .line 55
    :pswitch_0
    iget-object v0, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 56
    .line 57
    check-cast v0, Lhr/l;

    .line 58
    .line 59
    if-eqz v0, :cond_4

    .line 60
    .line 61
    invoke-virtual {v0}, Lhr/l;->l()V

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Lhr/l;->g:Ljava/util/Collection;

    .line 65
    .line 66
    iget-object v0, v0, Lhr/l;->f:Ljava/util/Collection;

    .line 67
    .line 68
    if-ne v0, p0, :cond_3

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_3
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 72
    .line 73
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 78
    .line 79
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    if-eqz v0, :cond_5

    .line 84
    .line 85
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 86
    .line 87
    check-cast v0, Ljp/o;

    .line 88
    .line 89
    iget-object v1, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 90
    .line 91
    iget-object v0, v0, Ljp/o;->f:Ljp/t;

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljp/t;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    check-cast v0, Ljava/util/Collection;

    .line 98
    .line 99
    if-eqz v0, :cond_5

    .line 100
    .line 101
    iput-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 102
    .line 103
    :cond_5
    :goto_1
    return-void

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    check-cast p0, Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Ljava/util/List;->lastIndexOf(Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 22
    .line 23
    check-cast p0, Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Ljava/util/List;->lastIndexOf(Ljava/lang/Object;)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0

    .line 30
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 34
    .line 35
    check-cast p0, Ljava/util/List;

    .line 36
    .line 37
    invoke-interface {p0, p1}, Ljava/util/List;->lastIndexOf(Ljava/lang/Object;)I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    return p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 1

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    invoke-virtual {p0}, Lhr/l;->l()V

    new-instance v0, Llp/d;

    .line 2
    invoke-direct {v0, p0}, Llp/d;-><init>(Lhr/l;)V

    return-object v0

    .line 3
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    new-instance v0, Ljp/l;

    .line 4
    invoke-direct {v0, p0}, Ljp/l;-><init>(Lhr/l;)V

    return-object v0

    .line 5
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 6
    new-instance v0, Lhr/k;

    invoke-direct {v0, p0}, Lhr/k;-><init>(Lhr/l;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 1

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 7
    invoke-virtual {p0}, Lhr/l;->l()V

    new-instance v0, Llp/d;

    .line 8
    invoke-direct {v0, p0, p1}, Llp/d;-><init>(Lhr/l;I)V

    return-object v0

    .line 9
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    new-instance v0, Ljp/l;

    .line 10
    invoke-direct {v0, p0, p1}, Ljp/l;-><init>(Lhr/l;I)V

    return-object v0

    .line 11
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 12
    new-instance v0, Lhr/k;

    invoke-direct {v0, p0, p1}, Lhr/k;-><init>(Lhr/l;I)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 2
    check-cast v0, Ljava/util/List;

    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    move-result-object p1

    .line 4
    invoke-virtual {p0}, Lhr/l;->k()V

    return-object p1

    .line 5
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 6
    check-cast v0, Ljava/util/List;

    .line 7
    invoke-interface {v0, p1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    move-result-object p1

    .line 8
    invoke-virtual {p0}, Lhr/l;->k()V

    return-object p1

    .line 9
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 10
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 11
    check-cast v0, Ljava/util/List;

    .line 12
    invoke-interface {v0, p1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    move-result-object p1

    .line 13
    iget-object v0, p0, Lhr/l;->j:Ljava/io/Serializable;

    check-cast v0, Lhr/t0;

    .line 14
    iget v1, v0, Lhr/t0;->h:I

    add-int/lit8 v1, v1, -0x1

    iput v1, v0, Lhr/t0;->h:I

    .line 15
    invoke-virtual {p0}, Lhr/l;->g()V

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 2

    iget v0, p0, Lhr/l;->d:I

    packed-switch v0, :pswitch_data_0

    .line 16
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 17
    invoke-interface {v0, p1}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    .line 18
    invoke-virtual {p0}, Lhr/l;->k()V

    :cond_0
    return p1

    .line 19
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 20
    invoke-interface {v0, p1}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    .line 21
    invoke-virtual {p0}, Lhr/l;->k()V

    :cond_1
    return p1

    .line 22
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 23
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    invoke-interface {v0, p1}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    .line 24
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    check-cast v0, Lhr/t0;

    .line 25
    iget v1, v0, Lhr/t0;->h:I

    add-int/lit8 v1, v1, -0x1

    iput v1, v0, Lhr/t0;->h:I

    .line 26
    invoke-virtual {p0}, Lhr/l;->g()V

    :cond_2
    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 3

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 18
    .line 19
    invoke-interface {v0, p1}, Ljava/util/Collection;->removeAll(Ljava/util/Collection;)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_1

    .line 24
    .line 25
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lhr/l;->k()V

    .line 31
    .line 32
    .line 33
    :cond_1
    move p0, p1

    .line 34
    :goto_0
    return p0

    .line 35
    :pswitch_0
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    const/4 p0, 0x0

    .line 42
    goto :goto_1

    .line 43
    :cond_2
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 47
    .line 48
    invoke-interface {v0, p1}, Ljava/util/Collection;->removeAll(Ljava/util/Collection;)Z

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    if-eqz p1, :cond_3

    .line 53
    .line 54
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 55
    .line 56
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Lhr/l;->k()V

    .line 60
    .line 61
    .line 62
    :cond_3
    move p0, p1

    .line 63
    :goto_1
    return p0

    .line 64
    :pswitch_1
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_4

    .line 69
    .line 70
    const/4 p0, 0x0

    .line 71
    goto :goto_2

    .line 72
    :cond_4
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 77
    .line 78
    invoke-interface {v1, p1}, Ljava/util/Collection;->removeAll(Ljava/util/Collection;)Z

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    if-eqz p1, :cond_5

    .line 83
    .line 84
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 85
    .line 86
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    iget-object v2, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 91
    .line 92
    check-cast v2, Lhr/t0;

    .line 93
    .line 94
    sub-int/2addr v1, v0

    .line 95
    iget v0, v2, Lhr/t0;->h:I

    .line 96
    .line 97
    add-int/2addr v0, v1

    .line 98
    iput v0, v2, Lhr/t0;->h:I

    .line 99
    .line 100
    invoke-virtual {p0}, Lhr/l;->g()V

    .line 101
    .line 102
    .line 103
    :cond_5
    move p0, p1

    .line 104
    :goto_2
    return p0

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 3

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 13
    .line 14
    invoke-interface {v0, p1}, Ljava/util/Collection;->retainAll(Ljava/util/Collection;)Z

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lhr/l;->k()V

    .line 26
    .line 27
    .line 28
    :cond_0
    return p1

    .line 29
    :pswitch_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 36
    .line 37
    invoke-interface {v0, p1}, Ljava/util/Collection;->retainAll(Ljava/util/Collection;)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_1

    .line 42
    .line 43
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 44
    .line 45
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Lhr/l;->k()V

    .line 49
    .line 50
    .line 51
    :cond_1
    return p1

    .line 52
    :pswitch_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Lhr/l;->size()I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 60
    .line 61
    invoke-interface {v1, p1}, Ljava/util/Collection;->retainAll(Ljava/util/Collection;)Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-eqz p1, :cond_2

    .line 66
    .line 67
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 68
    .line 69
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    iget-object v2, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 74
    .line 75
    check-cast v2, Lhr/t0;

    .line 76
    .line 77
    sub-int/2addr v1, v0

    .line 78
    iget v0, v2, Lhr/t0;->h:I

    .line 79
    .line 80
    add-int/2addr v0, v1

    .line 81
    iput v0, v2, Lhr/t0;->h:I

    .line 82
    .line 83
    invoke-virtual {p0}, Lhr/l;->g()V

    .line 84
    .line 85
    .line 86
    :cond_2
    return p1

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    check-cast p0, Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 22
    .line 23
    check-cast p0, Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 34
    .line 35
    check-cast p0, Ljava/util/List;

    .line 36
    .line 37
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final subList(II)Ljava/util/List;
    .locals 2

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    check-cast v0, Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v0, p1, p2}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iget-object p2, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 18
    .line 19
    check-cast p2, Lhr/l;

    .line 20
    .line 21
    if-nez p2, :cond_0

    .line 22
    .line 23
    move-object p2, p0

    .line 24
    :cond_0
    iget-object v0, p0, Lhr/l;->j:Ljava/io/Serializable;

    .line 25
    .line 26
    check-cast v0, Llp/f;

    .line 27
    .line 28
    instance-of v1, p1, Ljava/util/RandomAccess;

    .line 29
    .line 30
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 31
    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    new-instance v1, Llp/c;

    .line 35
    .line 36
    invoke-direct {v1, v0, p0, p1, p2}, Lhr/l;-><init>(Llp/f;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    new-instance v1, Lhr/l;

    .line 41
    .line 42
    invoke-direct {v1, v0, p0, p1, p2}, Lhr/l;-><init>(Llp/f;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 43
    .line 44
    .line 45
    :goto_0
    return-object v1

    .line 46
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 47
    .line 48
    .line 49
    iget-object v0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 50
    .line 51
    check-cast v0, Ljava/util/List;

    .line 52
    .line 53
    invoke-interface {v0, p1, p2}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    iget-object p2, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 58
    .line 59
    check-cast p2, Lhr/l;

    .line 60
    .line 61
    if-nez p2, :cond_2

    .line 62
    .line 63
    move-object p2, p0

    .line 64
    :cond_2
    iget-object v0, p0, Lhr/l;->j:Ljava/io/Serializable;

    .line 65
    .line 66
    check-cast v0, Ljp/o;

    .line 67
    .line 68
    instance-of v1, p1, Ljava/util/RandomAccess;

    .line 69
    .line 70
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 71
    .line 72
    if-eqz v1, :cond_3

    .line 73
    .line 74
    new-instance v1, Ljp/k;

    .line 75
    .line 76
    invoke-direct {v1, v0, p0, p1, p2}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    new-instance v1, Lhr/l;

    .line 81
    .line 82
    invoke-direct {v1, v0, p0, p1, p2}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 83
    .line 84
    .line 85
    :goto_1
    return-object v1

    .line 86
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 87
    .line 88
    .line 89
    iget-object v0, p0, Lhr/l;->j:Ljava/io/Serializable;

    .line 90
    .line 91
    check-cast v0, Lhr/t0;

    .line 92
    .line 93
    iget-object v1, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 94
    .line 95
    check-cast v1, Ljava/util/List;

    .line 96
    .line 97
    invoke-interface {v1, p1, p2}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    iget-object p2, p0, Lhr/l;->h:Ljava/util/AbstractCollection;

    .line 102
    .line 103
    check-cast p2, Lhr/l;

    .line 104
    .line 105
    if-nez p2, :cond_4

    .line 106
    .line 107
    move-object p2, p0

    .line 108
    :cond_4
    instance-of v1, p1, Ljava/util/RandomAccess;

    .line 109
    .line 110
    iget-object p0, p0, Lhr/l;->e:Ljava/lang/Object;

    .line 111
    .line 112
    if-eqz v1, :cond_5

    .line 113
    .line 114
    new-instance v1, Lhr/h;

    .line 115
    .line 116
    invoke-direct {v1, v0, p0, p1, p2}, Lhr/l;-><init>(Lhr/t0;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 117
    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_5
    new-instance v1, Lhr/l;

    .line 121
    .line 122
    invoke-direct {v1, v0, p0, p1, p2}, Lhr/l;-><init>(Lhr/t0;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 123
    .line 124
    .line 125
    :goto_2
    return-object v1

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lhr/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_0
    invoke-virtual {p0}, Lhr/l;->l()V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :pswitch_1
    invoke-virtual {p0}, Lhr/l;->e()V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lhr/l;->f:Ljava/util/Collection;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

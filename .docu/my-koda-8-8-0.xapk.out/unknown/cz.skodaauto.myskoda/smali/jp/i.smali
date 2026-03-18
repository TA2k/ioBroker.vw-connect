.class public Ljp/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/util/Iterator;

.field public f:Ljava/util/Collection;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lhr/d;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ljp/i;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ljp/i;->g:Ljava/lang/Object;

    iget-object p1, p1, Lhr/d;->e:Ljava/util/Map;

    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Ljp/i;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lhr/l;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ljp/i;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ljp/i;->g:Ljava/lang/Object;

    iget-object p1, p1, Lhr/l;->f:Ljava/util/Collection;

    iput-object p1, p0, Ljp/i;->f:Ljava/util/Collection;

    instance-of v0, p1, Ljava/util/List;

    if-eqz v0, :cond_0

    .line 4
    check-cast p1, Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->listIterator()Ljava/util/ListIterator;

    move-result-object p1

    goto :goto_0

    .line 5
    :cond_0
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p1

    .line 6
    :goto_0
    iput-object p1, p0, Ljp/i;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lhr/l;Ljava/util/ListIterator;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ljp/i;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ljp/i;->g:Ljava/lang/Object;

    iget-object p1, p1, Lhr/l;->f:Ljava/util/Collection;

    iput-object p1, p0, Ljp/i;->f:Ljava/util/Collection;

    iput-object p2, p0, Ljp/i;->e:Ljava/util/Iterator;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    iget-object v0, p0, Ljp/i;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lhr/l;

    .line 4
    .line 5
    invoke-virtual {v0}, Lhr/l;->l()V

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lhr/l;->f:Ljava/util/Collection;

    .line 9
    .line 10
    iget-object p0, p0, Ljp/i;->f:Ljava/util/Collection;

    .line 11
    .line 12
    if-ne v0, p0, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Ljp/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljp/i;->a()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Ljp/i;->e:Ljava/util/Iterator;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :pswitch_0
    iget-object p0, p0, Ljp/i;->e:Ljava/util/Iterator;

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Ljp/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljp/i;->a()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Ljp/i;->e:Ljava/util/Iterator;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_0
    iget-object v0, p0, Ljp/i;->e:Ljava/util/Iterator;

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Ljava/util/Map$Entry;

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Ljava/util/Collection;

    .line 29
    .line 30
    iput-object v1, p0, Ljp/i;->f:Ljava/util/Collection;

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Ljava/util/Collection;

    .line 41
    .line 42
    iget-object p0, p0, Ljp/i;->g:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Lhr/d;

    .line 45
    .line 46
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 47
    .line 48
    check-cast p0, Ljp/o;

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    check-cast v0, Ljava/util/List;

    .line 54
    .line 55
    instance-of v2, v0, Ljava/util/RandomAccess;

    .line 56
    .line 57
    const/4 v3, 0x0

    .line 58
    if-eqz v2, :cond_0

    .line 59
    .line 60
    new-instance v2, Ljp/k;

    .line 61
    .line 62
    invoke-direct {v2, p0, v1, v0, v3}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    new-instance v2, Lhr/l;

    .line 67
    .line 68
    invoke-direct {v2, p0, v1, v0, v3}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 69
    .line 70
    .line 71
    :goto_0
    new-instance p0, Ljp/v;

    .line 72
    .line 73
    invoke-direct {p0, v1, v2}, Ljp/v;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 2

    .line 1
    iget v0, p0, Ljp/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ljp/i;->e:Ljava/util/Iterator;

    .line 7
    .line 8
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Ljp/i;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lhr/l;

    .line 14
    .line 15
    invoke-virtual {p0}, Lhr/l;->k()V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_0
    iget-object v0, p0, Ljp/i;->f:Ljava/util/Collection;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x0

    .line 26
    :goto_0
    const-string v1, "no calls to next() since the last call to remove()"

    .line 27
    .line 28
    invoke-static {v1, v0}, Llp/ic;->d(Ljava/lang/String;Z)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ljp/i;->e:Ljava/util/Iterator;

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Ljp/i;->g:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lhr/d;

    .line 39
    .line 40
    iget-object v0, v0, Lhr/d;->h:Ljava/io/Serializable;

    .line 41
    .line 42
    check-cast v0, Ljp/o;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Ljp/i;->f:Ljava/util/Collection;

    .line 48
    .line 49
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 50
    .line 51
    .line 52
    iget-object v0, p0, Ljp/i;->f:Ljava/util/Collection;

    .line 53
    .line 54
    invoke-interface {v0}, Ljava/util/Collection;->clear()V

    .line 55
    .line 56
    .line 57
    const/4 v0, 0x0

    .line 58
    iput-object v0, p0, Ljp/i;->f:Ljava/util/Collection;

    .line 59
    .line 60
    return-void

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

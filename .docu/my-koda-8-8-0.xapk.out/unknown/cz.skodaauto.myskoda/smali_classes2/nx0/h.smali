.class public final Lnx0/h;
.super Ljava/util/AbstractCollection;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Collection;
.implements Lby0/b;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final add(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget p0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0

    .line 12
    :pswitch_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :pswitch_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public addAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    const-string p0, "elements"

    .line 12
    .line 13
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final clear()V
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lsy0/d;

    .line 9
    .line 10
    invoke-virtual {p0}, Lsy0/d;->clear()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lt2/f;

    .line 17
    .line 18
    invoke-virtual {p0}, Lt2/f;->clear()V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_1
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lnx0/f;

    .line 25
    .line 26
    invoke-virtual {p0}, Lnx0/f;->clear()V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lsy0/d;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Ljava/util/AbstractMap;->containsValue(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lt2/f;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Ljava/util/AbstractMap;->containsValue(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :pswitch_1
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lnx0/f;

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lnx0/f;->containsValue(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public isEmpty()Z
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lnx0/f;

    .line 14
    .line 15
    invoke-virtual {p0}, Lnx0/f;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result p0

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

.method public final iterator()Ljava/util/Iterator;
    .locals 6

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lsy0/g;

    .line 7
    .line 8
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lsy0/d;

    .line 11
    .line 12
    const-string v1, "builder"

    .line 13
    .line 14
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/16 v1, 0x8

    .line 18
    .line 19
    new-array v2, v1, [Lq2/j;

    .line 20
    .line 21
    const/4 v3, 0x0

    .line 22
    :goto_0
    if-ge v3, v1, :cond_0

    .line 23
    .line 24
    new-instance v4, Lsy0/k;

    .line 25
    .line 26
    const/4 v5, 0x2

    .line 27
    invoke-direct {v4, v5}, Lsy0/k;-><init>(I)V

    .line 28
    .line 29
    .line 30
    aput-object v4, v2, v3

    .line 31
    .line 32
    add-int/lit8 v3, v3, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-direct {v0, p0, v2}, Lsy0/e;-><init>(Lsy0/d;[Lq2/j;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_0
    new-instance v0, Lq2/f;

    .line 40
    .line 41
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lt2/f;

    .line 44
    .line 45
    const/16 v1, 0x8

    .line 46
    .line 47
    new-array v2, v1, [Lq2/j;

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    :goto_1
    if-ge v3, v1, :cond_1

    .line 51
    .line 52
    new-instance v4, Lq2/k;

    .line 53
    .line 54
    const/4 v5, 0x2

    .line 55
    invoke-direct {v4, v5}, Lq2/k;-><init>(I)V

    .line 56
    .line 57
    .line 58
    aput-object v4, v2, v3

    .line 59
    .line 60
    add-int/lit8 v3, v3, 0x1

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    invoke-direct {v0, p0, v2}, Lq2/d;-><init>(Lt2/f;[Lq2/j;)V

    .line 64
    .line 65
    .line 66
    return-object v0

    .line 67
    :pswitch_1
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p0, Lnx0/f;

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    new-instance v0, Lnx0/d;

    .line 75
    .line 76
    const/4 v1, 0x2

    .line 77
    invoke-direct {v0, p0, v1}, Lnx0/d;-><init>(Lnx0/f;I)V

    .line 78
    .line 79
    .line 80
    return-object v0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public remove(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lnx0/f;

    .line 14
    .line 15
    invoke-virtual {p0}, Lnx0/f;->c()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnx0/f;->i(Ljava/lang/Object;)I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-gez p1, :cond_0

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p0, p1}, Lnx0/f;->l(I)V

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    :goto_0
    return p0

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public removeAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    const-string v0, "elements"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lnx0/f;

    .line 19
    .line 20
    invoke-virtual {v0}, Lnx0/f;->c()V

    .line 21
    .line 22
    .line 23
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public retainAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    const-string v0, "elements"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lnx0/f;

    .line 19
    .line 20
    invoke-virtual {v0}, Lnx0/f;->c()V

    .line 21
    .line 22
    .line 23
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Lnx0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lsy0/d;

    .line 9
    .line 10
    invoke-virtual {p0}, Lsy0/d;->c()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    goto :goto_0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lt2/f;

    .line 18
    .line 19
    invoke-virtual {p0}, Lt2/f;->c()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    goto :goto_0

    .line 24
    :pswitch_1
    iget-object p0, p0, Lnx0/h;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lnx0/f;

    .line 27
    .line 28
    iget p0, p0, Lnx0/f;->l:I

    .line 29
    .line 30
    :goto_0
    return p0

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

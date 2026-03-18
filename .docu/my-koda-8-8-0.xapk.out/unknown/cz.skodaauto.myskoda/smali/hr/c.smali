.class public Lhr/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/util/Iterator;

.field public f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lhr/d;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lhr/c;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 12
    iget-object p1, p1, Lhr/d;->e:Ljava/util/Map;

    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Lhr/c;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lhr/e;Ljava/util/Iterator;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lhr/c;->d:I

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lhr/c;->e:Ljava/util/Iterator;

    iput-object p1, p0, Lhr/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lhr/l;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lhr/c;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 2
    iget-object p1, p1, Lhr/l;->f:Ljava/util/Collection;

    iput-object p1, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 3
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
    iput-object p1, p0, Lhr/c;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lhr/l;Ljava/util/ListIterator;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lhr/c;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 8
    iget-object p1, p1, Lhr/l;->f:Ljava/util/Collection;

    iput-object p1, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 9
    iput-object p2, p0, Lhr/c;->e:Ljava/util/Iterator;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    iget-object v0, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lhr/l;

    .line 4
    .line 5
    invoke-virtual {v0}, Lhr/l;->e()V

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lhr/l;->f:Ljava/util/Collection;

    .line 9
    .line 10
    iget-object p0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/util/Collection;

    .line 13
    .line 14
    if-ne v0, p0, :cond_0

    .line 15
    .line 16
    return-void

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
.end method

.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/c;->a()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/c;->e:Ljava/util/Iterator;

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
    iget-object p0, p0, Lhr/c;->e:Ljava/util/Iterator;

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
    :pswitch_1
    iget-object p0, p0, Lhr/c;->e:Ljava/util/Iterator;

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lhr/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/c;->a()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lhr/c;->e:Ljava/util/Iterator;

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
    iget-object v0, p0, Lhr/c;->e:Ljava/util/Iterator;

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
    iput-object v0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_1
    iget-object v0, p0, Lhr/c;->e:Ljava/util/Iterator;

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/util/Map$Entry;

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Ljava/util/Collection;

    .line 44
    .line 45
    iput-object v1, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 46
    .line 47
    iget-object p0, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Lhr/d;

    .line 50
    .line 51
    invoke-virtual {p0, v0}, Lhr/d;->a(Ljava/util/Map$Entry;)Lhr/d0;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 4

    .line 1
    iget v0, p0, Lhr/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/c;->e:Ljava/util/Iterator;

    .line 7
    .line 8
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lhr/l;

    .line 14
    .line 15
    iget-object v0, p0, Lhr/l;->i:Ljava/io/Serializable;

    .line 16
    .line 17
    check-cast v0, Lhr/t0;

    .line 18
    .line 19
    iget v1, v0, Lhr/t0;->h:I

    .line 20
    .line 21
    add-int/lit8 v1, v1, -0x1

    .line 22
    .line 23
    iput v1, v0, Lhr/t0;->h:I

    .line 24
    .line 25
    invoke-virtual {p0}, Lhr/l;->g()V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_0
    iget-object v0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, Ljava/util/Map$Entry;

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    const/4 v0, 0x1

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v0, 0x0

    .line 38
    :goto_0
    const-string v1, "no calls to next() since the last call to remove()"

    .line 39
    .line 40
    invoke-static {v1, v0}, Lkp/i9;->h(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    iget-object v0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v0, Ljava/util/Map$Entry;

    .line 46
    .line 47
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    check-cast v0, Ljava/util/Collection;

    .line 52
    .line 53
    iget-object v1, p0, Lhr/c;->e:Ljava/util/Iterator;

    .line 54
    .line 55
    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v1, Lhr/e;

    .line 61
    .line 62
    iget-object v1, v1, Lhr/e;->f:Lhr/t0;

    .line 63
    .line 64
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    iget v3, v1, Lhr/t0;->h:I

    .line 69
    .line 70
    sub-int/2addr v3, v2

    .line 71
    iput v3, v1, Lhr/t0;->h:I

    .line 72
    .line 73
    invoke-interface {v0}, Ljava/util/Collection;->clear()V

    .line 74
    .line 75
    .line 76
    const/4 v0, 0x0

    .line 77
    iput-object v0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 78
    .line 79
    return-void

    .line 80
    :pswitch_1
    iget-object v0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v0, Ljava/util/Collection;

    .line 83
    .line 84
    if-eqz v0, :cond_1

    .line 85
    .line 86
    const/4 v0, 0x1

    .line 87
    goto :goto_1

    .line 88
    :cond_1
    const/4 v0, 0x0

    .line 89
    :goto_1
    const-string v1, "no calls to next() since the last call to remove()"

    .line 90
    .line 91
    invoke-static {v1, v0}, Lkp/i9;->h(Ljava/lang/String;Z)V

    .line 92
    .line 93
    .line 94
    iget-object v0, p0, Lhr/c;->e:Ljava/util/Iterator;

    .line 95
    .line 96
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 97
    .line 98
    .line 99
    iget-object v0, p0, Lhr/c;->g:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lhr/d;

    .line 102
    .line 103
    iget-object v0, v0, Lhr/d;->h:Ljava/io/Serializable;

    .line 104
    .line 105
    check-cast v0, Lhr/t0;

    .line 106
    .line 107
    iget-object v1, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v1, Ljava/util/Collection;

    .line 110
    .line 111
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    iget v2, v0, Lhr/t0;->h:I

    .line 116
    .line 117
    sub-int/2addr v2, v1

    .line 118
    iput v2, v0, Lhr/t0;->h:I

    .line 119
    .line 120
    iget-object v0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v0, Ljava/util/Collection;

    .line 123
    .line 124
    invoke-interface {v0}, Ljava/util/Collection;->clear()V

    .line 125
    .line 126
    .line 127
    const/4 v0, 0x0

    .line 128
    iput-object v0, p0, Lhr/c;->f:Ljava/lang/Object;

    .line 129
    .line 130
    return-void

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

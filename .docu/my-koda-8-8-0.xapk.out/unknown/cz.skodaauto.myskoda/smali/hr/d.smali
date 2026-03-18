.class public Lhr/d;
.super Ljava/util/AbstractMap;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final transient e:Ljava/util/Map;

.field public transient f:Ljava/util/AbstractSet;

.field public transient g:Ljava/util/AbstractCollection;

.field public final synthetic h:Ljava/io/Serializable;


# direct methods
.method public synthetic constructor <init>(Ljava/io/Serializable;Ljava/util/Map;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhr/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/util/AbstractMap;-><init>()V

    .line 6
    .line 7
    .line 8
    iput-object p2, p0, Lhr/d;->e:Ljava/util/Map;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public a(Ljava/util/Map$Entry;)Lhr/d0;
    .locals 3

    .line 1
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 6
    .line 7
    check-cast p0, Lhr/t0;

    .line 8
    .line 9
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Ljava/util/Collection;

    .line 14
    .line 15
    check-cast p1, Ljava/util/List;

    .line 16
    .line 17
    instance-of v1, p1, Ljava/util/RandomAccess;

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    new-instance v1, Lhr/h;

    .line 23
    .line 24
    invoke-direct {v1, p0, v0, p1, v2}, Lhr/l;-><init>(Lhr/t0;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v1, Lhr/l;

    .line 29
    .line 30
    invoke-direct {v1, p0, v0, p1, v2}, Lhr/l;-><init>(Lhr/t0;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    new-instance p0, Lhr/d0;

    .line 34
    .line 35
    invoke-direct {p0, v0, v1}, Lhr/d0;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-object p0
.end method

.method public final clear()V
    .locals 3

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 7
    .line 8
    check-cast v0, Llp/f;

    .line 9
    .line 10
    iget-object v0, v0, Llp/f;->f:Llp/j;

    .line 11
    .line 12
    iget-object v1, p0, Lhr/d;->e:Ljava/util/Map;

    .line 13
    .line 14
    if-ne v1, v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0}, Llp/j;->values()Ljava/util/Collection;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, Ljava/util/Collection;

    .line 35
    .line 36
    invoke-interface {v1}, Ljava/util/Collection;->clear()V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    invoke-virtual {v0}, Llp/j;->clear()V

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_1
    new-instance v0, Llp/b;

    .line 45
    .line 46
    invoke-direct {v0, p0}, Llp/b;-><init>(Lhr/d;)V

    .line 47
    .line 48
    .line 49
    :goto_1
    invoke-virtual {v0}, Llp/b;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-eqz p0, :cond_2

    .line 54
    .line 55
    invoke-virtual {v0}, Llp/b;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Llp/b;->remove()V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    :goto_2
    return-void

    .line 63
    :pswitch_0
    iget-object v0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 64
    .line 65
    check-cast v0, Ljp/o;

    .line 66
    .line 67
    iget-object v1, p0, Lhr/d;->e:Ljava/util/Map;

    .line 68
    .line 69
    iget-object v2, v0, Ljp/o;->f:Ljp/t;

    .line 70
    .line 71
    if-ne v1, v2, :cond_4

    .line 72
    .line 73
    iget-object p0, v0, Ljp/o;->f:Ljp/t;

    .line 74
    .line 75
    invoke-virtual {p0}, Ljp/t;->values()Ljava/util/Collection;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-eqz v1, :cond_3

    .line 88
    .line 89
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    check-cast v1, Ljava/util/Collection;

    .line 94
    .line 95
    invoke-interface {v1}, Ljava/util/Collection;->clear()V

    .line 96
    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_3
    invoke-virtual {p0}, Ljp/t;->clear()V

    .line 100
    .line 101
    .line 102
    goto :goto_5

    .line 103
    :cond_4
    new-instance v0, Ljp/i;

    .line 104
    .line 105
    invoke-direct {v0, p0}, Ljp/i;-><init>(Lhr/d;)V

    .line 106
    .line 107
    .line 108
    :goto_4
    invoke-virtual {v0}, Ljp/i;->hasNext()Z

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    if-eqz p0, :cond_5

    .line 113
    .line 114
    invoke-virtual {v0}, Ljp/i;->next()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0}, Ljp/i;->remove()V

    .line 118
    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_5
    :goto_5
    return-void

    .line 122
    :pswitch_1
    iget-object v0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 123
    .line 124
    check-cast v0, Lhr/t0;

    .line 125
    .line 126
    iget-object v1, v0, Lhr/t0;->g:Ljava/util/Map;

    .line 127
    .line 128
    iget-object v2, p0, Lhr/d;->e:Ljava/util/Map;

    .line 129
    .line 130
    if-ne v2, v1, :cond_6

    .line 131
    .line 132
    invoke-virtual {v0}, Lhr/t0;->b()V

    .line 133
    .line 134
    .line 135
    goto :goto_7

    .line 136
    :cond_6
    new-instance v0, Lhr/c;

    .line 137
    .line 138
    invoke-direct {v0, p0}, Lhr/c;-><init>(Lhr/d;)V

    .line 139
    .line 140
    .line 141
    :goto_6
    invoke-virtual {v0}, Lhr/c;->hasNext()Z

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    if-eqz p0, :cond_7

    .line 146
    .line 147
    invoke-virtual {v0}, Lhr/c;->next()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0}, Lhr/c;->remove()V

    .line 151
    .line 152
    .line 153
    goto :goto_6

    .line 154
    :cond_7
    :goto_7
    return-void

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    goto :goto_0

    .line 16
    :catch_0
    const/4 p0, 0x0

    .line 17
    :goto_0
    return p0

    .line 18
    :pswitch_0
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    :try_start_1
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p0
    :try_end_1
    .catch Ljava/lang/ClassCastException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_1

    .line 27
    goto :goto_1

    .line 28
    :catch_1
    const/4 p0, 0x0

    .line 29
    :goto_1
    return p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    :try_start_2
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p0
    :try_end_2
    .catch Ljava/lang/ClassCastException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_2 .. :try_end_2} :catch_2

    .line 39
    goto :goto_2

    .line 40
    :catch_2
    const/4 p0, 0x0

    .line 41
    :goto_2
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

.method public final entrySet()Ljava/util/Set;
    .locals 1

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/d;->f:Ljava/util/AbstractSet;

    .line 7
    .line 8
    check-cast v0, Llp/a;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Llp/a;

    .line 13
    .line 14
    invoke-direct {v0, p0}, Llp/a;-><init>(Lhr/d;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lhr/d;->f:Ljava/util/AbstractSet;

    .line 18
    .line 19
    :cond_0
    return-object v0

    .line 20
    :pswitch_0
    iget-object v0, p0, Lhr/d;->f:Ljava/util/AbstractSet;

    .line 21
    .line 22
    check-cast v0, Ljp/h;

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    new-instance v0, Ljp/h;

    .line 27
    .line 28
    invoke-direct {v0, p0}, Ljp/h;-><init>(Lhr/d;)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lhr/d;->f:Ljava/util/AbstractSet;

    .line 32
    .line 33
    :cond_1
    return-object v0

    .line 34
    :pswitch_1
    iget-object v0, p0, Lhr/d;->f:Ljava/util/AbstractSet;

    .line 35
    .line 36
    check-cast v0, Lhr/b;

    .line 37
    .line 38
    if-nez v0, :cond_2

    .line 39
    .line 40
    new-instance v0, Lhr/b;

    .line 41
    .line 42
    invoke-direct {v0, p0}, Lhr/b;-><init>(Lhr/d;)V

    .line 43
    .line 44
    .line 45
    iput-object v0, p0, Lhr/d;->f:Ljava/util/AbstractSet;

    .line 46
    .line 47
    :cond_2
    return-object v0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    if-eq p0, p1, :cond_1

    .line 7
    .line 8
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    goto :goto_1

    .line 19
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 20
    :goto_1
    return p0

    .line 21
    :pswitch_0
    if-eq p0, p1, :cond_3

    .line 22
    .line 23
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-eqz p0, :cond_2

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    const/4 p0, 0x0

    .line 33
    goto :goto_3

    .line 34
    :cond_3
    :goto_2
    const/4 p0, 0x1

    .line 35
    :goto_3
    return p0

    .line 36
    :pswitch_1
    if-eq p0, p1, :cond_5

    .line 37
    .line 38
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 39
    .line 40
    invoke-interface {p0, p1}, Ljava/util/Map;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_4

    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_4
    const/4 p0, 0x0

    .line 48
    goto :goto_5

    .line 49
    :cond_5
    :goto_4
    const/4 p0, 0x1

    .line 50
    :goto_5
    return p0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    :try_start_0
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    goto :goto_0

    .line 17
    :catch_0
    move-object v0, v1

    .line 18
    :goto_0
    check-cast v0, Ljava/util/Collection;

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    goto :goto_2

    .line 23
    :cond_0
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 24
    .line 25
    check-cast p0, Llp/f;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    check-cast v0, Ljava/util/List;

    .line 31
    .line 32
    instance-of v2, v0, Ljava/util/RandomAccess;

    .line 33
    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    new-instance v2, Llp/c;

    .line 37
    .line 38
    invoke-direct {v2, p0, p1, v0, v1}, Lhr/l;-><init>(Llp/f;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 39
    .line 40
    .line 41
    :goto_1
    move-object v1, v2

    .line 42
    goto :goto_2

    .line 43
    :cond_1
    new-instance v2, Lhr/l;

    .line 44
    .line 45
    invoke-direct {v2, p0, p1, v0, v1}, Lhr/l;-><init>(Llp/f;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :goto_2
    return-object v1

    .line 50
    :pswitch_0
    iget-object v0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    const/4 v1, 0x0

    .line 56
    :try_start_1
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/ClassCastException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_1

    .line 60
    goto :goto_3

    .line 61
    :catch_1
    move-object v0, v1

    .line 62
    :goto_3
    check-cast v0, Ljava/util/Collection;

    .line 63
    .line 64
    if-nez v0, :cond_2

    .line 65
    .line 66
    goto :goto_5

    .line 67
    :cond_2
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 68
    .line 69
    check-cast p0, Ljp/o;

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    check-cast v0, Ljava/util/List;

    .line 75
    .line 76
    instance-of v2, v0, Ljava/util/RandomAccess;

    .line 77
    .line 78
    if-eqz v2, :cond_3

    .line 79
    .line 80
    new-instance v2, Ljp/k;

    .line 81
    .line 82
    invoke-direct {v2, p0, p1, v0, v1}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 83
    .line 84
    .line 85
    :goto_4
    move-object v1, v2

    .line 86
    goto :goto_5

    .line 87
    :cond_3
    new-instance v2, Lhr/l;

    .line 88
    .line 89
    invoke-direct {v2, p0, p1, v0, v1}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 90
    .line 91
    .line 92
    goto :goto_4

    .line 93
    :goto_5
    return-object v1

    .line 94
    :pswitch_1
    iget-object v0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    const/4 v1, 0x0

    .line 100
    :try_start_2
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v0
    :try_end_2
    .catch Ljava/lang/ClassCastException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_2 .. :try_end_2} :catch_2

    .line 104
    goto :goto_6

    .line 105
    :catch_2
    move-object v0, v1

    .line 106
    :goto_6
    check-cast v0, Ljava/util/Collection;

    .line 107
    .line 108
    if-nez v0, :cond_4

    .line 109
    .line 110
    goto :goto_8

    .line 111
    :cond_4
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 112
    .line 113
    check-cast p0, Lhr/t0;

    .line 114
    .line 115
    check-cast v0, Ljava/util/List;

    .line 116
    .line 117
    instance-of v2, v0, Ljava/util/RandomAccess;

    .line 118
    .line 119
    if-eqz v2, :cond_5

    .line 120
    .line 121
    new-instance v2, Lhr/h;

    .line 122
    .line 123
    invoke-direct {v2, p0, p1, v0, v1}, Lhr/l;-><init>(Lhr/t0;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 124
    .line 125
    .line 126
    :goto_7
    move-object v1, v2

    .line 127
    goto :goto_8

    .line 128
    :cond_5
    new-instance v2, Lhr/l;

    .line 129
    .line 130
    invoke-direct {v2, p0, p1, v0, v1}, Lhr/l;-><init>(Lhr/t0;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 131
    .line 132
    .line 133
    goto :goto_7

    .line 134
    :goto_8
    return-object v1

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Map;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public keySet()Ljava/util/Set;
    .locals 2

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 7
    .line 8
    check-cast p0, Llp/f;

    .line 9
    .line 10
    iget-object v0, p0, Llp/e;->d:Llp/a;

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    new-instance v0, Llp/a;

    .line 15
    .line 16
    iget-object v1, p0, Llp/f;->f:Llp/j;

    .line 17
    .line 18
    invoke-direct {v0, p0, v1}, Llp/a;-><init>(Llp/f;Ljava/util/Map;)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Llp/e;->d:Llp/a;

    .line 22
    .line 23
    :cond_0
    return-object v0

    .line 24
    :pswitch_0
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 25
    .line 26
    check-cast p0, Ljp/o;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljp/n;->b()Ljava/util/Set;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_1
    iget-object p0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 34
    .line 35
    check-cast p0, Lhr/t0;

    .line 36
    .line 37
    iget-object v0, p0, Lhr/o;->d:Lhr/e;

    .line 38
    .line 39
    if-nez v0, :cond_3

    .line 40
    .line 41
    iget-object v0, p0, Lhr/t0;->g:Ljava/util/Map;

    .line 42
    .line 43
    instance-of v1, v0, Ljava/util/NavigableMap;

    .line 44
    .line 45
    if-eqz v1, :cond_1

    .line 46
    .line 47
    new-instance v1, Lhr/g;

    .line 48
    .line 49
    check-cast v0, Ljava/util/NavigableMap;

    .line 50
    .line 51
    invoke-direct {v1, p0, v0}, Lhr/g;-><init>(Lhr/t0;Ljava/util/NavigableMap;)V

    .line 52
    .line 53
    .line 54
    :goto_0
    move-object v0, v1

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    instance-of v1, v0, Ljava/util/SortedMap;

    .line 57
    .line 58
    if-eqz v1, :cond_2

    .line 59
    .line 60
    new-instance v1, Lhr/j;

    .line 61
    .line 62
    check-cast v0, Ljava/util/SortedMap;

    .line 63
    .line 64
    invoke-direct {v1, p0, v0}, Lhr/j;-><init>(Lhr/t0;Ljava/util/SortedMap;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    new-instance v1, Lhr/e;

    .line 69
    .line 70
    invoke-direct {v1, p0, v0}, Lhr/e;-><init>(Lhr/t0;Ljava/util/Map;)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :goto_1
    iput-object v0, p0, Lhr/o;->d:Lhr/e;

    .line 75
    .line 76
    :cond_3
    return-object v0

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 7
    .line 8
    check-cast v0, Llp/f;

    .line 9
    .line 10
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 11
    .line 12
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/util/Collection;

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    new-instance p1, Ljava/util/ArrayList;

    .line 26
    .line 27
    const/4 v0, 0x3

    .line 28
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 32
    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 35
    .line 36
    .line 37
    invoke-interface {p0}, Ljava/util/Collection;->clear()V

    .line 38
    .line 39
    .line 40
    move-object p0, p1

    .line 41
    :goto_0
    return-object p0

    .line 42
    :pswitch_0
    iget-object v0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 43
    .line 44
    check-cast v0, Ljp/o;

    .line 45
    .line 46
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 47
    .line 48
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    check-cast p0, Ljava/util/Collection;

    .line 53
    .line 54
    if-nez p0, :cond_1

    .line 55
    .line 56
    const/4 p0, 0x0

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    new-instance p1, Ljava/util/ArrayList;

    .line 62
    .line 63
    const/4 v0, 0x3

    .line 64
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 68
    .line 69
    .line 70
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 71
    .line 72
    .line 73
    invoke-interface {p0}, Ljava/util/Collection;->clear()V

    .line 74
    .line 75
    .line 76
    move-object p0, p1

    .line 77
    :goto_1
    return-object p0

    .line 78
    :pswitch_1
    iget-object v0, p0, Lhr/d;->h:Ljava/io/Serializable;

    .line 79
    .line 80
    check-cast v0, Lhr/t0;

    .line 81
    .line 82
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 83
    .line 84
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    check-cast p0, Ljava/util/Collection;

    .line 89
    .line 90
    if-nez p0, :cond_2

    .line 91
    .line 92
    const/4 p0, 0x0

    .line 93
    goto :goto_2

    .line 94
    :cond_2
    iget-object p1, v0, Lhr/t0;->i:Lhr/s0;

    .line 95
    .line 96
    invoke-virtual {p1}, Lhr/s0;->get()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    check-cast p1, Ljava/util/List;

    .line 101
    .line 102
    check-cast p1, Ljava/util/List;

    .line 103
    .line 104
    invoke-interface {p1, p0}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    .line 105
    .line 106
    .line 107
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    iget v2, v0, Lhr/t0;->h:I

    .line 112
    .line 113
    sub-int/2addr v2, v1

    .line 114
    iput v2, v0, Lhr/t0;->h:I

    .line 115
    .line 116
    invoke-interface {p0}, Ljava/util/Collection;->clear()V

    .line 117
    .line 118
    .line 119
    move-object p0, p1

    .line 120
    :goto_2
    return-object p0

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final values()Ljava/util/Collection;
    .locals 2

    .line 1
    iget v0, p0, Lhr/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhr/d;->g:Ljava/util/AbstractCollection;

    .line 7
    .line 8
    check-cast v0, Lhr/n;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Lhr/n;

    .line 13
    .line 14
    const/4 v1, 0x6

    .line 15
    invoke-direct {v0, p0, v1}, Lhr/n;-><init>(Ljava/util/AbstractMap;I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lhr/d;->g:Ljava/util/AbstractCollection;

    .line 19
    .line 20
    :cond_0
    return-object v0

    .line 21
    :pswitch_0
    iget-object v0, p0, Lhr/d;->g:Ljava/util/AbstractCollection;

    .line 22
    .line 23
    check-cast v0, Lhr/n;

    .line 24
    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    new-instance v0, Lhr/n;

    .line 28
    .line 29
    const/4 v1, 0x4

    .line 30
    invoke-direct {v0, p0, v1}, Lhr/n;-><init>(Ljava/util/AbstractMap;I)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lhr/d;->g:Ljava/util/AbstractCollection;

    .line 34
    .line 35
    :cond_1
    return-object v0

    .line 36
    :pswitch_1
    iget-object v0, p0, Lhr/d;->g:Ljava/util/AbstractCollection;

    .line 37
    .line 38
    check-cast v0, Lhr/n;

    .line 39
    .line 40
    if-nez v0, :cond_2

    .line 41
    .line 42
    new-instance v0, Lhr/n;

    .line 43
    .line 44
    const/4 v1, 0x2

    .line 45
    invoke-direct {v0, p0, v1}, Lhr/n;-><init>(Ljava/util/AbstractMap;I)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Lhr/d;->g:Ljava/util/AbstractCollection;

    .line 49
    .line 50
    :cond_2
    return-object v0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

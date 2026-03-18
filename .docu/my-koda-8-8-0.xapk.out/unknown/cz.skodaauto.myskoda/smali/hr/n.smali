.class public final Lhr/n;
.super Ljava/util/AbstractCollection;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/io/Serializable;)V
    .locals 0

    .line 1
    iput p1, p0, Lhr/n;->d:I

    iput-object p2, p0, Lhr/n;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/AbstractMap;I)V
    .locals 0

    .line 2
    iput p2, p0, Lhr/n;->d:I

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    iput-object p1, p0, Lhr/n;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final clear()V
    .locals 1

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lhr/d;

    .line 9
    .line 10
    invoke-virtual {p0}, Lhr/d;->clear()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Llp/j;

    .line 17
    .line 18
    invoke-virtual {p0}, Llp/j;->clear()V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_1
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lhr/d;

    .line 25
    .line 26
    invoke-virtual {p0}, Lhr/d;->clear()V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_2
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Ljp/t;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljp/t;->clear()V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :pswitch_3
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lhr/d;

    .line 41
    .line 42
    invoke-virtual {p0}, Lhr/d;->clear()V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :pswitch_4
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lhr/v;

    .line 49
    .line 50
    invoke-virtual {p0}, Lhr/v;->clear()V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :pswitch_5
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p0, Lhr/t0;

    .line 57
    .line 58
    invoke-virtual {p0}, Lhr/t0;->b()V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public contains(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_1
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lhr/d;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Ljava/util/AbstractMap;->containsValue(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_2
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lhr/d;

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/util/AbstractMap;->containsValue(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0

    .line 29
    :pswitch_3
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lhr/d;

    .line 32
    .line 33
    invoke-interface {p0, p1}, Ljava/util/Map;->containsValue(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    return p0

    .line 38
    :pswitch_4
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lhr/t0;

    .line 41
    .line 42
    invoke-virtual {p0}, Lhr/o;->a()Lhr/d;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {p0}, Lhr/d;->values()Ljava/util/Collection;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    check-cast p0, Lhr/n;

    .line 51
    .line 52
    invoke-virtual {p0}, Lhr/n;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_1

    .line 61
    .line 62
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    check-cast v0, Ljava/util/Collection;

    .line 67
    .line 68
    invoke-interface {v0, p1}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-eqz v0, :cond_0

    .line 73
    .line 74
    const/4 p0, 0x1

    .line 75
    goto :goto_0

    .line 76
    :cond_1
    const/4 p0, 0x0

    .line 77
    :goto_0
    return p0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_0
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public isEmpty()Z
    .locals 1

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-super {p0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_1
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lhr/d;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_2
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lhr/d;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0

    .line 29
    :pswitch_3
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lhr/d;

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    return p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 2

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lhr/d;

    .line 9
    .line 10
    invoke-virtual {p0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v0, Llp/r;

    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    invoke-direct {v0, p0, v1}, Lhr/k1;-><init>(Ljava/util/Iterator;I)V

    .line 22
    .line 23
    .line 24
    return-object v0

    .line 25
    :pswitch_0
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Llp/j;

    .line 28
    .line 29
    invoke-virtual {p0}, Llp/j;->d()Ljava/util/Map;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    new-instance v0, Llp/g;

    .line 45
    .line 46
    const/4 v1, 0x2

    .line 47
    invoke-direct {v0, p0, v1}, Llp/g;-><init>(Llp/j;I)V

    .line 48
    .line 49
    .line 50
    move-object p0, v0

    .line 51
    :goto_0
    return-object p0

    .line 52
    :pswitch_1
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p0, Lhr/d;

    .line 55
    .line 56
    invoke-virtual {p0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    new-instance v0, Ljp/a0;

    .line 65
    .line 66
    invoke-direct {v0, p0}, Ljp/a0;-><init>(Ljava/util/Iterator;)V

    .line 67
    .line 68
    .line 69
    return-object v0

    .line 70
    :pswitch_2
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Ljp/t;

    .line 73
    .line 74
    invoke-virtual {p0}, Ljp/t;->d()Ljava/util/Map;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    if-eqz v0, :cond_1

    .line 79
    .line 80
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    goto :goto_1

    .line 89
    :cond_1
    new-instance v0, Ljp/p;

    .line 90
    .line 91
    const/4 v1, 0x2

    .line 92
    invoke-direct {v0, p0, v1}, Ljp/p;-><init>(Ljp/t;I)V

    .line 93
    .line 94
    .line 95
    move-object p0, v0

    .line 96
    :goto_1
    return-object p0

    .line 97
    :pswitch_3
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p0, Lhr/d;

    .line 100
    .line 101
    invoke-virtual {p0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    new-instance v0, Lhr/r0;

    .line 110
    .line 111
    const/4 v1, 0x0

    .line 112
    invoke-direct {v0, p0, v1}, Lhr/k1;-><init>(Ljava/util/Iterator;I)V

    .line 113
    .line 114
    .line 115
    return-object v0

    .line 116
    :pswitch_4
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p0, Lhr/v;

    .line 119
    .line 120
    invoke-virtual {p0}, Lhr/v;->b()Ljava/util/Map;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    if-eqz v0, :cond_2

    .line 125
    .line 126
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    goto :goto_2

    .line 135
    :cond_2
    new-instance v0, Lhr/r;

    .line 136
    .line 137
    const/4 v1, 0x2

    .line 138
    invoke-direct {v0, p0, v1}, Lhr/r;-><init>(Lhr/v;I)V

    .line 139
    .line 140
    .line 141
    move-object p0, v0

    .line 142
    :goto_2
    return-object p0

    .line 143
    :pswitch_5
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast p0, Lhr/t0;

    .line 146
    .line 147
    new-instance v0, Lhr/a;

    .line 148
    .line 149
    invoke-direct {v0, p0}, Lhr/a;-><init>(Lhr/t0;)V

    .line 150
    .line 151
    .line 152
    return-object v0

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public remove(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_1
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lhr/d;

    .line 14
    .line 15
    :try_start_0
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->remove(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    goto :goto_0

    .line 20
    :catch_0
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Ljava/util/Map$Entry;

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    invoke-static {p1, v2}, Llp/fg;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_0

    .line 49
    .line 50
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {v0, p0}, Lhr/d;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    const/4 p0, 0x1

    .line 58
    goto :goto_0

    .line 59
    :cond_1
    const/4 p0, 0x0

    .line 60
    :goto_0
    return p0

    .line 61
    :pswitch_2
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Lhr/d;

    .line 64
    .line 65
    :try_start_1
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->remove(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result p0
    :try_end_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_1

    .line 69
    goto :goto_1

    .line 70
    :catch_1
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_3

    .line 83
    .line 84
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    check-cast v1, Ljava/util/Map$Entry;

    .line 89
    .line 90
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    invoke-static {p1, v2}, Llp/hc;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-eqz v2, :cond_2

    .line 99
    .line 100
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-virtual {v0, p0}, Lhr/d;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    const/4 p0, 0x1

    .line 108
    goto :goto_1

    .line 109
    :cond_3
    const/4 p0, 0x0

    .line 110
    :goto_1
    return p0

    .line 111
    :pswitch_3
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Lhr/d;

    .line 114
    .line 115
    :try_start_2
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->remove(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p0
    :try_end_2
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_2 .. :try_end_2} :catch_2

    .line 119
    goto :goto_2

    .line 120
    :catch_2
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    :cond_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    if-eqz v1, :cond_5

    .line 133
    .line 134
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    check-cast v1, Ljava/util/Map$Entry;

    .line 139
    .line 140
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    invoke-static {p1, v2}, Lkp/h9;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    if-eqz v2, :cond_4

    .line 149
    .line 150
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    invoke-virtual {v0, p0}, Lhr/d;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    const/4 p0, 0x1

    .line 158
    goto :goto_2

    .line 159
    :cond_5
    const/4 p0, 0x0

    .line 160
    :goto_2
    return p0

    .line 161
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public removeAll(Ljava/util/Collection;)Z
    .locals 4

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_1
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lhr/d;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    :try_start_0
    move-object v1, p1

    .line 18
    check-cast v1, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-super {p0, v1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    throw p0
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    :catch_0
    new-instance p0, Ljava/util/HashSet;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    check-cast v2, Ljava/util/Map$Entry;

    .line 51
    .line 52
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-interface {p1, v3}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_1

    .line 61
    .line 62
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    invoke-virtual {p0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    iget-object p1, v0, Lhr/d;->h:Ljava/io/Serializable;

    .line 71
    .line 72
    check-cast p1, Llp/f;

    .line 73
    .line 74
    invoke-virtual {p1}, Llp/e;->b()Ljava/util/Set;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-interface {p1, p0}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    :goto_1
    return p0

    .line 83
    :pswitch_2
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Lhr/d;

    .line 86
    .line 87
    if-eqz p1, :cond_3

    .line 88
    .line 89
    :try_start_1
    move-object v1, p1

    .line 90
    check-cast v1, Ljava/util/Collection;

    .line 91
    .line 92
    invoke-super {p0, v1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    goto :goto_3

    .line 97
    :cond_3
    const/4 p0, 0x0

    .line 98
    throw p0
    :try_end_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_1

    .line 99
    :catch_1
    new-instance p0, Ljava/util/HashSet;

    .line 100
    .line 101
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    :cond_4
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    if-eqz v2, :cond_5

    .line 117
    .line 118
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    check-cast v2, Ljava/util/Map$Entry;

    .line 123
    .line 124
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    invoke-interface {p1, v3}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    if-eqz v3, :cond_4

    .line 133
    .line 134
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    invoke-virtual {p0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_5
    iget-object p1, v0, Lhr/d;->h:Ljava/io/Serializable;

    .line 143
    .line 144
    check-cast p1, Ljp/o;

    .line 145
    .line 146
    invoke-virtual {p1}, Ljp/n;->b()Ljava/util/Set;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    invoke-interface {p1, p0}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    :goto_3
    return p0

    .line 155
    :pswitch_3
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v0, Lhr/d;

    .line 158
    .line 159
    :try_start_2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    move-object v1, p1

    .line 163
    check-cast v1, Ljava/util/Collection;

    .line 164
    .line 165
    invoke-super {p0, v1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 166
    .line 167
    .line 168
    move-result p0
    :try_end_2
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_2 .. :try_end_2} :catch_2

    .line 169
    goto :goto_5

    .line 170
    :catch_2
    new-instance p0, Ljava/util/HashSet;

    .line 171
    .line 172
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    :cond_6
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 184
    .line 185
    .line 186
    move-result v2

    .line 187
    if-eqz v2, :cond_7

    .line 188
    .line 189
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    check-cast v2, Ljava/util/Map$Entry;

    .line 194
    .line 195
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v3

    .line 199
    invoke-interface {p1, v3}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v3

    .line 203
    if-eqz v3, :cond_6

    .line 204
    .line 205
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    invoke-virtual {p0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    goto :goto_4

    .line 213
    :cond_7
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    invoke-interface {p1, p0}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 218
    .line 219
    .line 220
    move-result p0

    .line 221
    :goto_5
    return p0

    .line 222
    nop

    .line 223
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public retainAll(Ljava/util/Collection;)Z
    .locals 4

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_1
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lhr/d;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    :try_start_0
    move-object v1, p1

    .line 18
    check-cast v1, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-super {p0, v1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    throw p0
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    :catch_0
    new-instance p0, Ljava/util/HashSet;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    check-cast v2, Ljava/util/Map$Entry;

    .line 51
    .line 52
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-interface {p1, v3}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_1

    .line 61
    .line 62
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    invoke-virtual {p0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    iget-object p1, v0, Lhr/d;->h:Ljava/io/Serializable;

    .line 71
    .line 72
    check-cast p1, Llp/f;

    .line 73
    .line 74
    invoke-virtual {p1}, Llp/e;->b()Ljava/util/Set;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-interface {p1, p0}, Ljava/util/Set;->retainAll(Ljava/util/Collection;)Z

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    :goto_1
    return p0

    .line 83
    :pswitch_2
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Lhr/d;

    .line 86
    .line 87
    if-eqz p1, :cond_3

    .line 88
    .line 89
    :try_start_1
    move-object v1, p1

    .line 90
    check-cast v1, Ljava/util/Collection;

    .line 91
    .line 92
    invoke-super {p0, v1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    goto :goto_3

    .line 97
    :cond_3
    const/4 p0, 0x0

    .line 98
    throw p0
    :try_end_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_1

    .line 99
    :catch_1
    new-instance p0, Ljava/util/HashSet;

    .line 100
    .line 101
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    :cond_4
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    if-eqz v2, :cond_5

    .line 117
    .line 118
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    check-cast v2, Ljava/util/Map$Entry;

    .line 123
    .line 124
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    invoke-interface {p1, v3}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    if-eqz v3, :cond_4

    .line 133
    .line 134
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    invoke-virtual {p0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_5
    iget-object p1, v0, Lhr/d;->h:Ljava/io/Serializable;

    .line 143
    .line 144
    check-cast p1, Ljp/o;

    .line 145
    .line 146
    invoke-virtual {p1}, Ljp/n;->b()Ljava/util/Set;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    invoke-interface {p1, p0}, Ljava/util/Set;->retainAll(Ljava/util/Collection;)Z

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    :goto_3
    return p0

    .line 155
    :pswitch_3
    iget-object v0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v0, Lhr/d;

    .line 158
    .line 159
    :try_start_2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    move-object v1, p1

    .line 163
    check-cast v1, Ljava/util/Collection;

    .line 164
    .line 165
    invoke-super {p0, v1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    .line 166
    .line 167
    .line 168
    move-result p0
    :try_end_2
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_2 .. :try_end_2} :catch_2

    .line 169
    goto :goto_5

    .line 170
    :catch_2
    new-instance p0, Ljava/util/HashSet;

    .line 171
    .line 172
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0}, Lhr/d;->entrySet()Ljava/util/Set;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    :cond_6
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 184
    .line 185
    .line 186
    move-result v2

    .line 187
    if-eqz v2, :cond_7

    .line 188
    .line 189
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    check-cast v2, Ljava/util/Map$Entry;

    .line 194
    .line 195
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v3

    .line 199
    invoke-interface {p1, v3}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v3

    .line 203
    if-eqz v3, :cond_6

    .line 204
    .line 205
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    invoke-virtual {p0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    goto :goto_4

    .line 213
    :cond_7
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    invoke-interface {p1, p0}, Ljava/util/Set;->retainAll(Ljava/util/Collection;)Z

    .line 218
    .line 219
    .line 220
    move-result p0

    .line 221
    :goto_5
    return p0

    .line 222
    nop

    .line 223
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Lhr/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lhr/d;

    .line 9
    .line 10
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 11
    .line 12
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Llp/j;

    .line 20
    .line 21
    invoke-virtual {p0}, Llp/j;->size()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :pswitch_1
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lhr/d;

    .line 29
    .line 30
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 31
    .line 32
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :pswitch_2
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Ljp/t;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljp/t;->size()I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    return p0

    .line 46
    :pswitch_3
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lhr/d;

    .line 49
    .line 50
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 51
    .line 52
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    return p0

    .line 57
    :pswitch_4
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Lhr/v;

    .line 60
    .line 61
    invoke-virtual {p0}, Lhr/v;->size()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    return p0

    .line 66
    :pswitch_5
    iget-object p0, p0, Lhr/n;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lhr/t0;

    .line 69
    .line 70
    iget p0, p0, Lhr/t0;->h:I

    .line 71
    .line 72
    return p0

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

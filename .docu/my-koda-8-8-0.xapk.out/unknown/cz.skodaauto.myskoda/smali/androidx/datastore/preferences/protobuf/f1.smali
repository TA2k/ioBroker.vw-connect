.class public Landroidx/datastore/preferences/protobuf/f1;
.super Ljava/util/AbstractSet;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/AbstractMap;


# direct methods
.method public synthetic constructor <init>(Ljava/util/AbstractMap;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/datastore/preferences/protobuf/f1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/util/AbstractSet;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final add(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/Map$Entry;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 15
    .line 16
    check-cast p0, Lcom/google/protobuf/y0;

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Ljava/lang/Comparable;

    .line 23
    .line 24
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {p0, v0, p1}, Lcom/google/protobuf/y0;->f(Ljava/lang/Comparable;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 p0, 0x0

    .line 34
    :goto_0
    return p0

    .line 35
    :pswitch_0
    check-cast p1, Ljava/util/Map$Entry;

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_1

    .line 42
    .line 43
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 44
    .line 45
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 46
    .line 47
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    check-cast v0, Ljava/lang/Comparable;

    .line 52
    .line 53
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->b(Ljava/lang/Comparable;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    const/4 p0, 0x1

    .line 61
    goto :goto_1

    .line 62
    :cond_1
    const/4 p0, 0x0

    .line 63
    :goto_1
    return p0

    .line 64
    :pswitch_1
    check-cast p1, Ljava/util/Map$Entry;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-nez v0, :cond_2

    .line 71
    .line 72
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 73
    .line 74
    check-cast p0, Lcom/google/android/gms/internal/measurement/p6;

    .line 75
    .line 76
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    check-cast v0, Ljava/lang/Comparable;

    .line 81
    .line 82
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-virtual {p0, v0, p1}, Lcom/google/android/gms/internal/measurement/p6;->c(Ljava/lang/Comparable;Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    const/4 p0, 0x1

    .line 90
    goto :goto_2

    .line 91
    :cond_2
    const/4 p0, 0x0

    .line 92
    :goto_2
    return p0

    .line 93
    :pswitch_2
    check-cast p1, Ljava/util/Map$Entry;

    .line 94
    .line 95
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-nez v0, :cond_3

    .line 100
    .line 101
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 102
    .line 103
    check-cast p0, Landroidx/datastore/preferences/protobuf/c1;

    .line 104
    .line 105
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    check-cast v0, Ljava/lang/Comparable;

    .line 110
    .line 111
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-virtual {p0, v0, p1}, Landroidx/datastore/preferences/protobuf/c1;->g(Ljava/lang/Comparable;Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    const/4 p0, 0x1

    .line 119
    goto :goto_3

    .line 120
    :cond_3
    const/4 p0, 0x0

    .line 121
    :goto_3
    return p0

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final clear()V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 7
    .line 8
    check-cast p0, Lcom/google/protobuf/y0;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/protobuf/y0;->clear()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 15
    .line 16
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 17
    .line 18
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->clear()V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_1
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 23
    .line 24
    check-cast p0, Lcom/google/android/gms/internal/measurement/p6;

    .line 25
    .line 26
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/p6;->clear()V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_2
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 31
    .line 32
    check-cast p0, Landroidx/datastore/preferences/protobuf/c1;

    .line 33
    .line 34
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/c1;->clear()V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/Map$Entry;

    .line 7
    .line 8
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 9
    .line 10
    check-cast p0, Lcom/google/protobuf/y0;

    .line 11
    .line 12
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p0, v0}, Lcom/google/protobuf/y0;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    if-eq p0, p1, :cond_1

    .line 25
    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 38
    :goto_1
    return p0

    .line 39
    :pswitch_0
    check-cast p1, Ljava/util/Map$Entry;

    .line 40
    .line 41
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 46
    .line 47
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 48
    .line 49
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    const/4 v0, 0x1

    .line 58
    if-eq p0, p1, :cond_3

    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    if-eqz p0, :cond_2

    .line 62
    .line 63
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    if-eqz p0, :cond_2

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_2
    move v0, v1

    .line 71
    :cond_3
    :goto_2
    return v0

    .line 72
    :pswitch_1
    check-cast p1, Ljava/util/Map$Entry;

    .line 73
    .line 74
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 79
    .line 80
    check-cast p0, Lcom/google/android/gms/internal/measurement/p6;

    .line 81
    .line 82
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/p6;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    const/4 v0, 0x1

    .line 91
    if-eq p0, p1, :cond_5

    .line 92
    .line 93
    const/4 v1, 0x0

    .line 94
    if-eqz p0, :cond_4

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-eqz p0, :cond_4

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_4
    move v0, v1

    .line 104
    :cond_5
    :goto_3
    return v0

    .line 105
    :pswitch_2
    check-cast p1, Ljava/util/Map$Entry;

    .line 106
    .line 107
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 108
    .line 109
    check-cast p0, Landroidx/datastore/preferences/protobuf/c1;

    .line 110
    .line 111
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    invoke-virtual {p0, v0}, Landroidx/datastore/preferences/protobuf/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    if-eq p0, p1, :cond_7

    .line 124
    .line 125
    if-eqz p0, :cond_6

    .line 126
    .line 127
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-eqz p0, :cond_6

    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_6
    const/4 p0, 0x0

    .line 135
    goto :goto_5

    .line 136
    :cond_7
    :goto_4
    const/4 p0, 0x1

    .line 137
    :goto_5
    return p0

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public iterator()Ljava/util/Iterator;
    .locals 2

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroidx/datastore/preferences/protobuf/e1;

    .line 7
    .line 8
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 9
    .line 10
    check-cast p0, Lcom/google/protobuf/y0;

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    invoke-direct {v0, p0, v1}, Landroidx/datastore/preferences/protobuf/e1;-><init>(Ljava/util/AbstractMap;I)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Landroidx/datastore/preferences/protobuf/e1;

    .line 18
    .line 19
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 20
    .line 21
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 22
    .line 23
    const/4 v1, 0x2

    .line 24
    invoke-direct {v0, p0, v1}, Landroidx/datastore/preferences/protobuf/e1;-><init>(Ljava/util/AbstractMap;I)V

    .line 25
    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Landroidx/datastore/preferences/protobuf/e1;

    .line 29
    .line 30
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 31
    .line 32
    check-cast p0, Lcom/google/android/gms/internal/measurement/p6;

    .line 33
    .line 34
    invoke-direct {v0, p0}, Landroidx/datastore/preferences/protobuf/e1;-><init>(Lcom/google/android/gms/internal/measurement/p6;)V

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    :pswitch_2
    new-instance v0, Landroidx/datastore/preferences/protobuf/e1;

    .line 39
    .line 40
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 41
    .line 42
    check-cast p0, Landroidx/datastore/preferences/protobuf/c1;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    invoke-direct {v0, p0, v1}, Landroidx/datastore/preferences/protobuf/e1;-><init>(Ljava/util/AbstractMap;I)V

    .line 46
    .line 47
    .line 48
    return-object v0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/Map$Entry;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 15
    .line 16
    check-cast p0, Lcom/google/protobuf/y0;

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-virtual {p0, p1}, Lcom/google/protobuf/y0;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
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
    :pswitch_0
    check-cast p1, Ljava/util/Map$Entry;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_1

    .line 36
    .line 37
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 38
    .line 39
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 40
    .line 41
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    const/4 p0, 0x1

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    const/4 p0, 0x0

    .line 51
    :goto_1
    return p0

    .line 52
    :pswitch_1
    check-cast p1, Ljava/util/Map$Entry;

    .line 53
    .line 54
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_2

    .line 59
    .line 60
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 61
    .line 62
    check-cast p0, Lcom/google/android/gms/internal/measurement/p6;

    .line 63
    .line 64
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/p6;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    const/4 p0, 0x1

    .line 72
    goto :goto_2

    .line 73
    :cond_2
    const/4 p0, 0x0

    .line 74
    :goto_2
    return p0

    .line 75
    :pswitch_2
    check-cast p1, Ljava/util/Map$Entry;

    .line 76
    .line 77
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/f1;->contains(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_3

    .line 82
    .line 83
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 84
    .line 85
    check-cast p0, Landroidx/datastore/preferences/protobuf/c1;

    .line 86
    .line 87
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/c1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    const/4 p0, 0x1

    .line 95
    goto :goto_3

    .line 96
    :cond_3
    const/4 p0, 0x0

    .line 97
    :goto_3
    return p0

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 7
    .line 8
    check-cast p0, Lcom/google/protobuf/y0;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/protobuf/y0;->size()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 16
    .line 17
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 18
    .line 19
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->size()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :pswitch_1
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 25
    .line 26
    check-cast p0, Lcom/google/android/gms/internal/measurement/p6;

    .line 27
    .line 28
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/p6;->size()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :pswitch_2
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/f1;->e:Ljava/util/AbstractMap;

    .line 34
    .line 35
    check-cast p0, Landroidx/datastore/preferences/protobuf/c1;

    .line 36
    .line 37
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/c1;->size()I

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
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

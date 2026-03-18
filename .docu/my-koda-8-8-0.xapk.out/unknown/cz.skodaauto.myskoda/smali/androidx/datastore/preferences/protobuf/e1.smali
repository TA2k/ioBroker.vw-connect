.class public final Landroidx/datastore/preferences/protobuf/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Z

.field public g:Ljava/util/Iterator;

.field public final synthetic h:Ljava/util/AbstractMap;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/gms/internal/measurement/p6;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Landroidx/datastore/preferences/protobuf/e1;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    const/4 p1, -0x1

    iput p1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/AbstractMap;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/datastore/preferences/protobuf/e1;->d:I

    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    const/4 p1, -0x1

    iput p1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 11
    .line 12
    check-cast v0, Lcom/google/protobuf/y0;

    .line 13
    .line 14
    iget-object v0, v0, Lcom/google/protobuf/y0;->f:Ljava/util/Map;

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 25
    .line 26
    :cond_0
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 34
    .line 35
    check-cast v0, Landroidx/datastore/preferences/protobuf/c1;

    .line 36
    .line 37
    iget-object v0, v0, Landroidx/datastore/preferences/protobuf/c1;->e:Ljava/util/Map;

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iput-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 48
    .line 49
    :cond_1
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 50
    .line 51
    return-object p0

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public b()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 11
    .line 12
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 13
    .line 14
    iget-object v0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 25
    .line 26
    :cond_0
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 34
    .line 35
    check-cast v0, Lcom/google/android/gms/internal/measurement/p6;

    .line 36
    .line 37
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/p6;->f:Ljava/util/Map;

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iput-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 48
    .line 49
    :cond_1
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e1;->g:Ljava/util/Iterator;

    .line 50
    .line 51
    return-object p0

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final hasNext()Z
    .locals 4

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    add-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 11
    .line 12
    check-cast v2, Lcom/google/protobuf/y0;

    .line 13
    .line 14
    iget-object v3, v2, Lcom/google/protobuf/y0;->e:Ljava/util/List;

    .line 15
    .line 16
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-lt v0, v3, :cond_1

    .line 21
    .line 22
    iget-object v0, v2, Lcom/google/protobuf/y0;->f:Ljava/util/Map;

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->a()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v1, 0x0

    .line 42
    :cond_1
    :goto_0
    return v1

    .line 43
    :pswitch_0
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 44
    .line 45
    const/4 v1, 0x1

    .line 46
    add-int/2addr v0, v1

    .line 47
    iget-object v2, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 48
    .line 49
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 50
    .line 51
    iget v3, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 52
    .line 53
    if-lt v0, v3, :cond_3

    .line 54
    .line 55
    iget-object v0, v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 56
    .line 57
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    const/4 v2, 0x0

    .line 62
    if-nez v0, :cond_2

    .line 63
    .line 64
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->b()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_2

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_2
    move v1, v2

    .line 76
    :cond_3
    :goto_1
    return v1

    .line 77
    :pswitch_1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 78
    .line 79
    const/4 v1, 0x1

    .line 80
    add-int/2addr v0, v1

    .line 81
    iget-object v2, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 82
    .line 83
    check-cast v2, Lcom/google/android/gms/internal/measurement/p6;

    .line 84
    .line 85
    iget v3, v2, Lcom/google/android/gms/internal/measurement/p6;->e:I

    .line 86
    .line 87
    if-lt v0, v3, :cond_5

    .line 88
    .line 89
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/p6;->f:Ljava/util/Map;

    .line 90
    .line 91
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    const/4 v2, 0x0

    .line 96
    if-nez v0, :cond_4

    .line 97
    .line 98
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->b()Ljava/util/Iterator;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-eqz p0, :cond_4

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_4
    move v1, v2

    .line 110
    :cond_5
    :goto_2
    return v1

    .line 111
    :pswitch_2
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 112
    .line 113
    const/4 v1, 0x1

    .line 114
    add-int/2addr v0, v1

    .line 115
    iget-object v2, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 116
    .line 117
    check-cast v2, Landroidx/datastore/preferences/protobuf/c1;

    .line 118
    .line 119
    iget-object v3, v2, Landroidx/datastore/preferences/protobuf/c1;->d:Ljava/util/List;

    .line 120
    .line 121
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    if-lt v0, v3, :cond_7

    .line 126
    .line 127
    iget-object v0, v2, Landroidx/datastore/preferences/protobuf/c1;->e:Ljava/util/Map;

    .line 128
    .line 129
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    if-nez v0, :cond_6

    .line 134
    .line 135
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->a()Ljava/util/Iterator;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 140
    .line 141
    .line 142
    move-result p0

    .line 143
    if-eqz p0, :cond_6

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_6
    const/4 v1, 0x0

    .line 147
    :cond_7
    :goto_3
    return v1

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 8
    .line 9
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 10
    .line 11
    add-int/2addr v1, v0

    .line 12
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 13
    .line 14
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 15
    .line 16
    check-cast v0, Lcom/google/protobuf/y0;

    .line 17
    .line 18
    iget-object v2, v0, Lcom/google/protobuf/y0;->e:Ljava/util/List;

    .line 19
    .line 20
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-ge v1, v2, :cond_0

    .line 25
    .line 26
    iget-object v0, v0, Lcom/google/protobuf/y0;->e:Ljava/util/List;

    .line 27
    .line 28
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 29
    .line 30
    invoke-interface {v0, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Ljava/util/Map$Entry;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->a()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    check-cast p0, Ljava/util/Map$Entry;

    .line 46
    .line 47
    :goto_0
    return-object p0

    .line 48
    :pswitch_0
    const/4 v0, 0x1

    .line 49
    iput-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 50
    .line 51
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 52
    .line 53
    add-int/2addr v1, v0

    .line 54
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 55
    .line 56
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 57
    .line 58
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 59
    .line 60
    iget v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 61
    .line 62
    if-ge v1, v2, :cond_1

    .line 63
    .line 64
    iget-object p0, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 65
    .line 66
    aget-object p0, p0, v1

    .line 67
    .line 68
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->b()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ljava/util/Map$Entry;

    .line 80
    .line 81
    :goto_1
    return-object p0

    .line 82
    :pswitch_1
    const/4 v0, 0x1

    .line 83
    iput-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 84
    .line 85
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 86
    .line 87
    add-int/2addr v1, v0

    .line 88
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 89
    .line 90
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 91
    .line 92
    check-cast v0, Lcom/google/android/gms/internal/measurement/p6;

    .line 93
    .line 94
    iget v2, v0, Lcom/google/android/gms/internal/measurement/p6;->e:I

    .line 95
    .line 96
    if-ge v1, v2, :cond_2

    .line 97
    .line 98
    iget-object p0, v0, Lcom/google/android/gms/internal/measurement/p6;->d:[Ljava/lang/Object;

    .line 99
    .line 100
    aget-object p0, p0, v1

    .line 101
    .line 102
    check-cast p0, Lcom/google/android/gms/internal/measurement/q6;

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_2
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->b()Ljava/util/Iterator;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Ljava/util/Map$Entry;

    .line 114
    .line 115
    :goto_2
    return-object p0

    .line 116
    :pswitch_2
    const/4 v0, 0x1

    .line 117
    iput-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 118
    .line 119
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 120
    .line 121
    add-int/2addr v1, v0

    .line 122
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 123
    .line 124
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 125
    .line 126
    check-cast v0, Landroidx/datastore/preferences/protobuf/c1;

    .line 127
    .line 128
    iget-object v2, v0, Landroidx/datastore/preferences/protobuf/c1;->d:Ljava/util/List;

    .line 129
    .line 130
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-ge v1, v2, :cond_3

    .line 135
    .line 136
    iget-object v0, v0, Landroidx/datastore/preferences/protobuf/c1;->d:Ljava/util/List;

    .line 137
    .line 138
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 139
    .line 140
    invoke-interface {v0, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    check-cast p0, Ljava/util/Map$Entry;

    .line 145
    .line 146
    goto :goto_3

    .line 147
    :cond_3
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->a()Ljava/util/Iterator;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    check-cast p0, Ljava/util/Map$Entry;

    .line 156
    .line 157
    :goto_3
    return-object p0

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 4

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->d:I

    .line 2
    .line 3
    const-string v1, "remove() was called before next()"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object v3, p0, Landroidx/datastore/preferences/protobuf/e1;->h:Ljava/util/AbstractMap;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast v3, Lcom/google/protobuf/y0;

    .line 12
    .line 13
    iget-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    iput-boolean v2, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 18
    .line 19
    sget v0, Lcom/google/protobuf/y0;->j:I

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/google/protobuf/y0;->b()V

    .line 22
    .line 23
    .line 24
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 25
    .line 26
    iget-object v1, v3, Lcom/google/protobuf/y0;->e:Ljava/util/List;

    .line 27
    .line 28
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-ge v0, v1, :cond_0

    .line 33
    .line 34
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 35
    .line 36
    add-int/lit8 v1, v0, -0x1

    .line 37
    .line 38
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 39
    .line 40
    invoke-virtual {v3, v0}, Lcom/google/protobuf/y0;->g(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->a()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 49
    .line 50
    .line 51
    :goto_0
    return-void

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :pswitch_0
    check-cast v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 59
    .line 60
    iget-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 61
    .line 62
    if-eqz v0, :cond_3

    .line 63
    .line 64
    iput-boolean v2, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 65
    .line 66
    sget v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->j:I

    .line 67
    .line 68
    invoke-virtual {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g()V

    .line 69
    .line 70
    .line 71
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 72
    .line 73
    iget v1, v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 74
    .line 75
    if-ge v0, v1, :cond_2

    .line 76
    .line 77
    add-int/lit8 v1, v0, -0x1

    .line 78
    .line 79
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 80
    .line 81
    invoke-virtual {v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_2
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->b()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 90
    .line 91
    .line 92
    :goto_1
    return-void

    .line 93
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 94
    .line 95
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :pswitch_1
    iget-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 100
    .line 101
    if-eqz v0, :cond_5

    .line 102
    .line 103
    iput-boolean v2, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 104
    .line 105
    check-cast v3, Lcom/google/android/gms/internal/measurement/p6;

    .line 106
    .line 107
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/p6;->f()V

    .line 108
    .line 109
    .line 110
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 111
    .line 112
    iget v1, v3, Lcom/google/android/gms/internal/measurement/p6;->e:I

    .line 113
    .line 114
    if-ge v0, v1, :cond_4

    .line 115
    .line 116
    add-int/lit8 v1, v0, -0x1

    .line 117
    .line 118
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 119
    .line 120
    invoke-virtual {v3, v0}, Lcom/google/android/gms/internal/measurement/p6;->d(I)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_4
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->b()Ljava/util/Iterator;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 129
    .line 130
    .line 131
    :goto_2
    return-void

    .line 132
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 133
    .line 134
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw p0

    .line 138
    :pswitch_2
    check-cast v3, Landroidx/datastore/preferences/protobuf/c1;

    .line 139
    .line 140
    iget-boolean v0, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 141
    .line 142
    if-eqz v0, :cond_7

    .line 143
    .line 144
    iput-boolean v2, p0, Landroidx/datastore/preferences/protobuf/e1;->f:Z

    .line 145
    .line 146
    sget v0, Landroidx/datastore/preferences/protobuf/c1;->i:I

    .line 147
    .line 148
    invoke-virtual {v3}, Landroidx/datastore/preferences/protobuf/c1;->b()V

    .line 149
    .line 150
    .line 151
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 152
    .line 153
    iget-object v1, v3, Landroidx/datastore/preferences/protobuf/c1;->d:Ljava/util/List;

    .line 154
    .line 155
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    if-ge v0, v1, :cond_6

    .line 160
    .line 161
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 162
    .line 163
    add-int/lit8 v1, v0, -0x1

    .line 164
    .line 165
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e1;->e:I

    .line 166
    .line 167
    invoke-virtual {v3, v0}, Landroidx/datastore/preferences/protobuf/c1;->h(I)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    goto :goto_3

    .line 171
    :cond_6
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/e1;->a()Ljava/util/Iterator;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 176
    .line 177
    .line 178
    :goto_3
    return-void

    .line 179
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 180
    .line 181
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p0

    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

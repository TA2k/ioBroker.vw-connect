.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;
.super Ljava/util/AbstractMap;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic j:I


# instance fields
.field public d:[Ljava/lang/Object;

.field public e:I

.field public f:Ljava/util/Map;

.field public g:Z

.field public volatile h:Landroidx/datastore/preferences/protobuf/f1;

.field public i:Ljava/util/Map;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractMap;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 7
    .line 8
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->i:Ljava/util/Map;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Set;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 10
    .line 11
    :goto_0
    check-cast p0, Ljava/util/Set;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    goto :goto_0
.end method

.method public final b(Ljava/lang/Comparable;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d(Ljava/lang/Comparable;)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-ltz v0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 11
    .line 12
    aget-object p0, p0, v0

    .line 13
    .line 14
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 15
    .line 16
    invoke-virtual {p0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->setValue(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g()V

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 25
    .line 26
    const/16 v2, 0x10

    .line 27
    .line 28
    if-nez v1, :cond_1

    .line 29
    .line 30
    new-array v1, v2, [Ljava/lang/Object;

    .line 31
    .line 32
    iput-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 33
    .line 34
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 35
    .line 36
    neg-int v0, v0

    .line 37
    if-lt v0, v2, :cond_2

    .line 38
    .line 39
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f()Ljava/util/SortedMap;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_2
    iget v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 49
    .line 50
    if-ne v1, v2, :cond_3

    .line 51
    .line 52
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 53
    .line 54
    const/16 v2, 0xf

    .line 55
    .line 56
    aget-object v1, v1, v2

    .line 57
    .line 58
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 59
    .line 60
    iput v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 61
    .line 62
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f()Ljava/util/SortedMap;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    iget-object v3, v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->d:Ljava/lang/Comparable;

    .line 67
    .line 68
    iget-object v1, v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->e:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-interface {v2, v3, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    :cond_3
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 74
    .line 75
    add-int/lit8 v2, v0, 0x1

    .line 76
    .line 77
    array-length v3, v1

    .line 78
    rsub-int/lit8 v3, v0, 0xf

    .line 79
    .line 80
    invoke-static {v1, v0, v1, v2, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 81
    .line 82
    .line 83
    iget-object v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 84
    .line 85
    new-instance v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 86
    .line 87
    invoke-direct {v2, p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;Ljava/lang/Comparable;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    aput-object v2, v1, v0

    .line 91
    .line 92
    iget p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 93
    .line 94
    add-int/lit8 p1, p1, 0x1

    .line 95
    .line 96
    iput p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 97
    .line 98
    const/4 p0, 0x0

    .line 99
    return-object p0
.end method

.method public final c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 2
    .line 3
    if-ge p1, v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    aget-object p0, p0, p1

    .line 8
    .line 9
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 13
    .line 14
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(I)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final clear()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g()V

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 13
    .line 14
    :cond_0
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Map;->clear()V

    .line 25
    .line 26
    .line 27
    :cond_1
    return-void
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    check-cast p1, Ljava/lang/Comparable;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d(Ljava/lang/Comparable;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-gez v0, :cond_1

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public final d(Ljava/lang/Comparable;)I
    .locals 4

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, -0x1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-ltz v1, :cond_2

    .line 7
    .line 8
    iget-object v3, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 9
    .line 10
    aget-object v3, v3, v1

    .line 11
    .line 12
    check-cast v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 13
    .line 14
    iget-object v3, v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->d:Ljava/lang/Comparable;

    .line 15
    .line 16
    invoke-interface {p1, v3}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-lez v3, :cond_0

    .line 21
    .line 22
    add-int/lit8 v0, v0, 0x1

    .line 23
    .line 24
    neg-int p0, v0

    .line 25
    return p0

    .line 26
    :cond_0
    if-eqz v3, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    return v1

    .line 30
    :cond_2
    :goto_0
    if-gt v2, v1, :cond_5

    .line 31
    .line 32
    add-int v0, v2, v1

    .line 33
    .line 34
    div-int/lit8 v0, v0, 0x2

    .line 35
    .line 36
    iget-object v3, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 37
    .line 38
    aget-object v3, v3, v0

    .line 39
    .line 40
    check-cast v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 41
    .line 42
    iget-object v3, v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->d:Ljava/lang/Comparable;

    .line 43
    .line 44
    invoke-interface {p1, v3}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-gez v3, :cond_3

    .line 49
    .line 50
    add-int/lit8 v1, v0, -0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    if-lez v3, :cond_4

    .line 54
    .line 55
    add-int/lit8 v2, v0, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_4
    return v0

    .line 59
    :cond_5
    add-int/lit8 v2, v2, 0x1

    .line 60
    .line 61
    neg-int p0, v2

    .line 62
    return p0
.end method

.method public final e(I)Ljava/lang/Object;
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 5
    .line 6
    aget-object v1, v0, p1

    .line 7
    .line 8
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 9
    .line 10
    iget-object v1, v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->e:Ljava/lang/Object;

    .line 11
    .line 12
    iget v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 13
    .line 14
    sub-int/2addr v2, p1

    .line 15
    add-int/lit8 v2, v2, -0x1

    .line 16
    .line 17
    add-int/lit8 v3, p1, 0x1

    .line 18
    .line 19
    invoke-static {v0, v3, v0, p1, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 20
    .line 21
    .line 22
    iget p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 23
    .line 24
    add-int/lit8 p1, p1, -0x1

    .line 25
    .line 26
    iput p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 27
    .line 28
    iget-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 29
    .line 30
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    if-nez p1, :cond_0

    .line 35
    .line 36
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f()Ljava/util/SortedMap;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-interface {p1}, Ljava/util/SortedMap;->entrySet()Ljava/util/Set;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 49
    .line 50
    iget v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 51
    .line 52
    new-instance v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 53
    .line 54
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    check-cast v4, Ljava/util/Map$Entry;

    .line 59
    .line 60
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    check-cast v5, Ljava/lang/Comparable;

    .line 65
    .line 66
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    invoke-direct {v3, p0, v5, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;-><init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;Ljava/lang/Comparable;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    aput-object v3, v0, v2

    .line 74
    .line 75
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 76
    .line 77
    add-int/lit8 v0, v0, 0x1

    .line 78
    .line 79
    iput v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 80
    .line 81
    invoke-interface {p1}, Ljava/util/Iterator;->remove()V

    .line 82
    .line 83
    .line 84
    :cond_0
    return-object v1
.end method

.method public final entrySet()Ljava/util/Set;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->h:Landroidx/datastore/preferences/protobuf/f1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/datastore/preferences/protobuf/f1;

    .line 6
    .line 7
    const/4 v1, 0x2

    .line 8
    invoke-direct {v0, p0, v1}, Landroidx/datastore/preferences/protobuf/f1;-><init>(Ljava/util/AbstractMap;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->h:Landroidx/datastore/preferences/protobuf/f1;

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->h:Landroidx/datastore/preferences/protobuf/f1;

    .line 14
    .line 15
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    invoke-super {p0, p1}, Ljava/util/AbstractMap;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :cond_1
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->size()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->size()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    const/4 v2, 0x0

    .line 24
    if-ne v0, v1, :cond_6

    .line 25
    .line 26
    iget v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 27
    .line 28
    iget v3, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 29
    .line 30
    if-ne v1, v3, :cond_5

    .line 31
    .line 32
    move v3, v2

    .line 33
    :goto_0
    if-ge v3, v1, :cond_3

    .line 34
    .line 35
    invoke-virtual {p0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    invoke-virtual {p1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    invoke-virtual {v4, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-nez v4, :cond_2

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    if-eq v1, v0, :cond_4

    .line 54
    .line 55
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 56
    .line 57
    iget-object p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 58
    .line 59
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    return p0

    .line 64
    :cond_4
    :goto_1
    const/4 p0, 0x1

    .line 65
    return p0

    .line 66
    :cond_5
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->entrySet()Ljava/util/Set;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-virtual {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->entrySet()Ljava/util/Set;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    return p0

    .line 79
    :cond_6
    :goto_2
    return v2
.end method

.method public final f()Ljava/util/SortedMap;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 13
    .line 14
    instance-of v0, v0, Ljava/util/TreeMap;

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    new-instance v0, Ljava/util/TreeMap;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/TreeMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/util/TreeMap;->descendingMap()Ljava/util/NavigableMap;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->i:Ljava/util/Map;

    .line 30
    .line 31
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 32
    .line 33
    check-cast p0, Ljava/util/SortedMap;

    .line 34
    .line 35
    return-object p0
.end method

.method public final g()V
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g:Z

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Ljava/lang/Comparable;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d(Ljava/lang/Comparable;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-ltz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 10
    .line 11
    aget-object p0, p0, v0

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->e:Ljava/lang/Object;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 19
    .line 20
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    move v2, v1

    .line 5
    :goto_0
    if-ge v1, v0, :cond_0

    .line 6
    .line 7
    iget-object v3, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d:[Ljava/lang/Object;

    .line 8
    .line 9
    aget-object v3, v3, v1

    .line 10
    .line 11
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    add-int/2addr v2, v3

    .line 16
    add-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-lez v0, :cond_1

    .line 26
    .line 27
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    add-int/2addr p0, v2

    .line 34
    return p0

    .line 35
    :cond_1
    return v2
.end method

.method public final bridge synthetic put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Comparable;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->b(Ljava/lang/Comparable;Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g()V

    .line 2
    .line 3
    .line 4
    check-cast p1, Ljava/lang/Comparable;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->d(Ljava/lang/Comparable;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-ltz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    const/4 p0, 0x0

    .line 26
    return-object p0

    .line 27
    :cond_1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 28
    .line 29
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public final size()I
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    add-int/2addr p0, v0

    .line 10
    return p0
.end method

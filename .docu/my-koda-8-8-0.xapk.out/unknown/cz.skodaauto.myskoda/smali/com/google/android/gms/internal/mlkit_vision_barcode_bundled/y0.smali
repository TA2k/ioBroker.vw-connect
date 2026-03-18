.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;


# instance fields
.field public final a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

.field public b:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;-><init>()V

    iput-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 2
    new-instance p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    invoke-direct {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;-><init>()V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->d()V

    .line 4
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->d()V

    return-void
.end method

.method public static a(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;Ljava/lang/Object;)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    shl-int/lit8 p0, p0, 0x3

    .line 6
    .line 7
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t0;->e(I)I

    .line 8
    .line 9
    .line 10
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j0;

    .line 15
    .line 16
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 17
    .line 18
    :cond_0
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z2;->d:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z2;

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    throw p0
.end method

.method public static h(Ljava/util/Map$Entry;)Z
    .locals 0

    .line 1
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    throw p0
.end method

.method public static final i(Ljava/util/Map$Entry;)I
    .locals 1

    .line 1
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    throw p0
.end method


# virtual methods
.method public final b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;
    .locals 5

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 7
    .line 8
    iget v1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    :goto_0
    if-ge v2, v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iget-object v4, v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->d:Ljava/lang/Comparable;

    .line 18
    .line 19
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 20
    .line 21
    iget-object v3, v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->e:Ljava/lang/Object;

    .line 22
    .line 23
    invoke-virtual {v0, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->e(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    add-int/lit8 v2, v2, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->a()Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Ljava/util/Map$Entry;

    .line 48
    .line 49
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 54
    .line 55
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {v0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->e(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    return-object v0
.end method

.method public final c()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-static {}, Ljava/util/Collections;->emptyIterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->entrySet()Ljava/util/Set;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Landroidx/datastore/preferences/protobuf/f1;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/f1;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final bridge synthetic clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d()V
    .locals 7

    .line 1
    iget-boolean v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->b:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 7
    .line 8
    iget v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    move v3, v2

    .line 12
    :goto_0
    if-ge v3, v1, :cond_2

    .line 13
    .line 14
    invoke-virtual {v0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    iget-object v4, v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->e:Ljava/lang/Object;

    .line 19
    .line 20
    instance-of v5, v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 21
    .line 22
    if-eqz v5, :cond_1

    .line 23
    .line 24
    check-cast v4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;

    .line 25
    .line 26
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    sget-object v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->c:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;

    .line 30
    .line 31
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    invoke-virtual {v5, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f2;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-interface {v5, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->b(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g1;->g()V

    .line 43
    .line 44
    .line 45
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    iget-boolean v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g:Z

    .line 49
    .line 50
    if-nez v1, :cond_4

    .line 51
    .line 52
    :goto_1
    iget v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 53
    .line 54
    if-ge v2, v1, :cond_3

    .line 55
    .line 56
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    iget-object v1, v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;->d:Ljava/lang/Comparable;

    .line 61
    .line 62
    check-cast v1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    add-int/lit8 v2, v2, 0x1

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->a()Ljava/util/Set;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-eqz v2, :cond_4

    .line 83
    .line 84
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    check-cast v2, Ljava/util/Map$Entry;

    .line 89
    .line 90
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    check-cast v2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 95
    .line 96
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_4
    iget-boolean v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g:Z

    .line 101
    .line 102
    const/4 v2, 0x1

    .line 103
    if-nez v1, :cond_7

    .line 104
    .line 105
    iget-object v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 106
    .line 107
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_5

    .line 112
    .line 113
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_5
    iget-object v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 117
    .line 118
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    :goto_3
    iput-object v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->f:Ljava/util/Map;

    .line 123
    .line 124
    iget-object v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->i:Ljava/util/Map;

    .line 125
    .line 126
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-eqz v1, :cond_6

    .line 131
    .line 132
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_6
    iget-object v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->i:Ljava/util/Map;

    .line 136
    .line 137
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    :goto_4
    iput-object v1, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->i:Ljava/util/Map;

    .line 142
    .line 143
    iput-boolean v2, v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->g:Z

    .line 144
    .line 145
    :cond_7
    iput-boolean v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->b:Z

    .line 146
    .line 147
    return-void
.end method

.method public final e(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n1;->a:Ljava/nio/charset/Charset;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y2;

    .line 10
    .line 11
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z2;->d:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z2;

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    throw p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 14
    .line 15
    iget-object p1, p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final f()Z
    .locals 4

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 2
    .line 3
    iget v0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->e:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :goto_0
    if-ge v2, v0, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->c(I)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o2;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-static {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->h(Ljava/util/Map$Entry;)Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-nez v3, :cond_0

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->a()Ljava/util/Set;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_3

    .line 36
    .line 37
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Ljava/util/Map$Entry;

    .line 42
    .line 43
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->h(Ljava/util/Map$Entry;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-nez v0, :cond_2

    .line 48
    .line 49
    :goto_1
    return v1

    .line 50
    :cond_3
    const/4 p0, 0x1

    .line 51
    return p0
.end method

.method public final g(Ljava/util/Map$Entry;)V
    .locals 0

    .line 1
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/e1;

    .line 6
    .line 7
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    throw p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/y0;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n2;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

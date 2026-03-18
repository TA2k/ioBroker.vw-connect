.class public final Lcom/google/crypto/tink/shaded/protobuf/h0;
.super Lcom/google/crypto/tink/shaded/protobuf/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Ljava/lang/Class;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/h0;->c:Ljava/lang/Class;

    .line 12
    .line 13
    return-void
.end method

.method public static d(JLjava/lang/Object;I)Ljava/util/List;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/util/List;

    .line 8
    .line 9
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    instance-of v1, v0, Lcom/google/crypto/tink/shaded/protobuf/g0;

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/f0;

    .line 20
    .line 21
    invoke-direct {v0, p3}, Lcom/google/crypto/tink/shaded/protobuf/f0;-><init>(I)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    instance-of v1, v0, Lcom/google/crypto/tink/shaded/protobuf/w0;

    .line 26
    .line 27
    if-eqz v1, :cond_1

    .line 28
    .line 29
    instance-of v1, v0, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 34
    .line 35
    invoke-interface {v0, p3}, Lcom/google/crypto/tink/shaded/protobuf/a0;->a(I)Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    new-instance v0, Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-direct {v0, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 43
    .line 44
    .line 45
    :goto_0
    invoke-static {p2, p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object v0

    .line 49
    :cond_2
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/h0;->c:Ljava/lang/Class;

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v1, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_3

    .line 60
    .line 61
    new-instance v1, Ljava/util/ArrayList;

    .line 62
    .line 63
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    add-int/2addr v2, p3

    .line 68
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 72
    .line 73
    .line 74
    invoke-static {p2, p0, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_3
    instance-of v1, v0, Lcom/google/crypto/tink/shaded/protobuf/g1;

    .line 79
    .line 80
    if-eqz v1, :cond_4

    .line 81
    .line 82
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/f0;

    .line 83
    .line 84
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    add-int/2addr v2, p3

    .line 89
    invoke-direct {v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/f0;-><init>(I)V

    .line 90
    .line 91
    .line 92
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/g1;

    .line 93
    .line 94
    invoke-virtual {v1, v0}, Lcom/google/crypto/tink/shaded/protobuf/f0;->addAll(Ljava/util/Collection;)Z

    .line 95
    .line 96
    .line 97
    invoke-static {p2, p0, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    return-object v1

    .line 101
    :cond_4
    instance-of v1, v0, Lcom/google/crypto/tink/shaded/protobuf/w0;

    .line 102
    .line 103
    if-eqz v1, :cond_5

    .line 104
    .line 105
    instance-of v1, v0, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 106
    .line 107
    if-eqz v1, :cond_5

    .line 108
    .line 109
    move-object v1, v0

    .line 110
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 111
    .line 112
    move-object v2, v1

    .line 113
    check-cast v2, Lcom/google/crypto/tink/shaded/protobuf/b;

    .line 114
    .line 115
    iget-boolean v2, v2, Lcom/google/crypto/tink/shaded/protobuf/b;->d:Z

    .line 116
    .line 117
    if-nez v2, :cond_5

    .line 118
    .line 119
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    add-int/2addr v0, p3

    .line 124
    invoke-interface {v1, v0}, Lcom/google/crypto/tink/shaded/protobuf/a0;->a(I)Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 125
    .line 126
    .line 127
    move-result-object p3

    .line 128
    invoke-static {p2, p0, p1, p3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    return-object p3

    .line 132
    :cond_5
    return-object v0
.end method


# virtual methods
.method public final a(JLjava/lang/Object;)V
    .locals 2

    .line 1
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {p0, p3, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/List;

    .line 8
    .line 9
    instance-of v0, p0, Lcom/google/crypto/tink/shaded/protobuf/g0;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/g0;

    .line 14
    .line 15
    invoke-interface {p0}, Lcom/google/crypto/tink/shaded/protobuf/g0;->getUnmodifiableView()Lcom/google/crypto/tink/shaded/protobuf/g0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/h0;->c:Ljava/lang/Class;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    instance-of v0, p0, Lcom/google/crypto/tink/shaded/protobuf/w0;

    .line 34
    .line 35
    if-eqz v0, :cond_3

    .line 36
    .line 37
    instance-of v0, p0, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 38
    .line 39
    if-eqz v0, :cond_3

    .line 40
    .line 41
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 42
    .line 43
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/b;

    .line 44
    .line 45
    iget-boolean p1, p0, Lcom/google/crypto/tink/shaded/protobuf/b;->d:Z

    .line 46
    .line 47
    if-eqz p1, :cond_2

    .line 48
    .line 49
    const/4 p1, 0x0

    .line 50
    iput-boolean p1, p0, Lcom/google/crypto/tink/shaded/protobuf/b;->d:Z

    .line 51
    .line 52
    :cond_2
    :goto_0
    return-void

    .line 53
    :cond_3
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    :goto_1
    invoke-static {p3, p1, p2, p0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public final b(Ljava/lang/Object;JLjava/lang/Object;)V
    .locals 2

    .line 1
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {p0, p4, p2, p3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/List;

    .line 8
    .line 9
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    invoke-static {p2, p3, p1, p4}, Lcom/google/crypto/tink/shaded/protobuf/h0;->d(JLjava/lang/Object;I)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p4

    .line 17
    invoke-interface {p4}, Ljava/util/List;->size()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-lez v0, :cond_0

    .line 26
    .line 27
    if-lez v1, :cond_0

    .line 28
    .line 29
    invoke-interface {p4, p0}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 30
    .line 31
    .line 32
    :cond_0
    if-lez v0, :cond_1

    .line 33
    .line 34
    move-object p0, p4

    .line 35
    :cond_1
    invoke-static {p1, p2, p3, p0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final c(JLjava/lang/Object;)Ljava/util/List;
    .locals 0

    .line 1
    const/16 p0, 0xa

    .line 2
    .line 3
    invoke-static {p1, p2, p3, p0}, Lcom/google/crypto/tink/shaded/protobuf/h0;->d(JLjava/lang/Object;I)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.class public final Lcom/google/protobuf/b0;
.super Lcom/google/protobuf/c0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(JLjava/lang/Object;)V
    .locals 0

    .line 1
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 2
    .line 3
    invoke-virtual {p0, p3, p1, p2}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/protobuf/t;

    .line 8
    .line 9
    check-cast p0, Lcom/google/protobuf/b;

    .line 10
    .line 11
    iget-boolean p1, p0, Lcom/google/protobuf/b;->d:Z

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    const/4 p1, 0x0

    .line 16
    iput-boolean p1, p0, Lcom/google/protobuf/b;->d:Z

    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final b(Ljava/lang/Object;JLjava/lang/Object;)V
    .locals 3

    .line 1
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcom/google/protobuf/t;

    .line 8
    .line 9
    invoke-virtual {p0, p4, p2, p3}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lcom/google/protobuf/t;

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result p4

    .line 19
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-lez p4, :cond_1

    .line 24
    .line 25
    if-lez v1, :cond_1

    .line 26
    .line 27
    move-object v2, v0

    .line 28
    check-cast v2, Lcom/google/protobuf/b;

    .line 29
    .line 30
    iget-boolean v2, v2, Lcom/google/protobuf/b;->d:Z

    .line 31
    .line 32
    if-nez v2, :cond_0

    .line 33
    .line 34
    add-int/2addr v1, p4

    .line 35
    invoke-interface {v0, v1}, Lcom/google/protobuf/t;->a(I)Lcom/google/protobuf/t;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    :cond_0
    invoke-interface {v0, p0}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 40
    .line 41
    .line 42
    :cond_1
    if-lez p4, :cond_2

    .line 43
    .line 44
    move-object p0, v0

    .line 45
    :cond_2
    invoke-static {p1, p2, p3, p0}, Lcom/google/protobuf/m1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

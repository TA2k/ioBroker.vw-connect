.class public final Lcom/google/protobuf/y;
.super Lcom/google/protobuf/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/protobuf/z;
.implements Ljava/util/RandomAccess;


# instance fields
.field public final e:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/protobuf/y;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/protobuf/y;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    .line 3
    invoke-direct {p0, v0}, Lcom/google/protobuf/b;-><init>(Z)V

    .line 4
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 5
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-direct {p0, v0}, Lcom/google/protobuf/y;-><init>(Ljava/util/ArrayList;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 1

    const/4 v0, 0x1

    .line 1
    invoke-direct {p0, v0}, Lcom/google/protobuf/b;-><init>(Z)V

    .line 2
    iput-object p1, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final a(I)Lcom/google/protobuf/t;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-lt p1, v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 15
    .line 16
    .line 17
    new-instance p0, Lcom/google/protobuf/y;

    .line 18
    .line 19
    invoke-direct {p0, v0}, Lcom/google/protobuf/y;-><init>(Ljava/util/ArrayList;)V

    .line 20
    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public final add(ILjava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p2, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/protobuf/b;->c()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {v0, p1, p2}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 12
    .line 13
    add-int/lit8 p1, p1, 0x1

    .line 14
    .line 15
    iput p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 16
    .line 17
    return-void
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 1

    .line 3
    invoke-virtual {p0}, Lcom/google/protobuf/b;->c()V

    .line 4
    instance-of v0, p2, Lcom/google/protobuf/z;

    if-eqz v0, :cond_0

    check-cast p2, Lcom/google/protobuf/z;

    invoke-interface {p2}, Lcom/google/protobuf/z;->getUnderlyingElements()Ljava/util/List;

    move-result-object p2

    .line 5
    :cond_0
    iget-object v0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    invoke-interface {v0, p1, p2}, Ljava/util/List;->addAll(ILjava/util/Collection;)Z

    move-result p1

    .line 6
    iget p2, p0, Ljava/util/AbstractList;->modCount:I

    add-int/lit8 p2, p2, 0x1

    iput p2, p0, Ljava/util/AbstractList;->modCount:I

    return p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    .line 2
    invoke-virtual {p0, v0, p1}, Lcom/google/protobuf/y;->addAll(ILjava/util/Collection;)Z

    move-result p0

    return p0
.end method

.method public final b(I)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final clear()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/protobuf/b;->c()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 7
    .line 8
    .line 9
    iget v0, p0, Ljava/util/AbstractList;->modCount:I

    .line 10
    .line 11
    add-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    iput v0, p0, Ljava/util/AbstractList;->modCount:I

    .line 14
    .line 15
    return-void
.end method

.method public final f(Lcom/google/protobuf/e;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/protobuf/b;->c()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 5
    .line 6
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    iget p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 10
    .line 11
    add-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    iput p1, p0, Ljava/util/AbstractList;->modCount:I

    .line 14
    .line 15
    return-void
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    instance-of v1, v0, Ljava/lang/String;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    check-cast v0, Ljava/lang/String;

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    instance-of v1, v0, Lcom/google/protobuf/e;

    .line 15
    .line 16
    if-eqz v1, :cond_3

    .line 17
    .line 18
    check-cast v0, Lcom/google/protobuf/e;

    .line 19
    .line 20
    sget-object v1, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 21
    .line 22
    invoke-virtual {v0}, Lcom/google/protobuf/e;->size()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-nez v2, :cond_1

    .line 27
    .line 28
    const-string v1, ""

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    new-instance v2, Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, v0, Lcom/google/protobuf/e;->e:[B

    .line 34
    .line 35
    invoke-virtual {v0}, Lcom/google/protobuf/e;->g()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    invoke-virtual {v0}, Lcom/google/protobuf/e;->size()I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    invoke-direct {v2, v3, v4, v5, v1}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 44
    .line 45
    .line 46
    move-object v1, v2

    .line 47
    :goto_0
    invoke-virtual {v0}, Lcom/google/protobuf/e;->g()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    iget-object v3, v0, Lcom/google/protobuf/e;->e:[B

    .line 52
    .line 53
    invoke-virtual {v0}, Lcom/google/protobuf/e;->size()I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    add-int/2addr v0, v2

    .line 58
    sget-object v4, Lcom/google/protobuf/p1;->a:Lcom/google/protobuf/b1;

    .line 59
    .line 60
    invoke-virtual {v4, v3, v2, v0}, Lcom/google/protobuf/b1;->c([BII)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_2

    .line 65
    .line 66
    invoke-interface {p0, p1, v1}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    :cond_2
    return-object v1

    .line 70
    :cond_3
    check-cast v0, [B

    .line 71
    .line 72
    new-instance v1, Ljava/lang/String;

    .line 73
    .line 74
    sget-object v2, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 75
    .line 76
    invoke-direct {v1, v0, v2}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 77
    .line 78
    .line 79
    sget-object v2, Lcom/google/protobuf/p1;->a:Lcom/google/protobuf/b1;

    .line 80
    .line 81
    const/4 v3, 0x0

    .line 82
    array-length v4, v0

    .line 83
    invoke-virtual {v2, v0, v3, v4}, Lcom/google/protobuf/b1;->c([BII)I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-nez v0, :cond_4

    .line 88
    .line 89
    invoke-interface {p0, p1, v1}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    :cond_4
    return-object v1
.end method

.method public final getUnderlyingElements()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getUnmodifiableView()Lcom/google/protobuf/z;
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/google/protobuf/b;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/protobuf/h1;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lcom/google/protobuf/h1;-><init>(Lcom/google/protobuf/y;)V

    .line 8
    .line 9
    .line 10
    return-object v0

    .line 11
    :cond_0
    return-object p0
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/protobuf/b;->c()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 5
    .line 6
    invoke-interface {v0, p1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iget v0, p0, Ljava/util/AbstractList;->modCount:I

    .line 11
    .line 12
    add-int/lit8 v0, v0, 0x1

    .line 13
    .line 14
    iput v0, p0, Ljava/util/AbstractList;->modCount:I

    .line 15
    .line 16
    instance-of p0, p1, Ljava/lang/String;

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    check-cast p1, Ljava/lang/String;

    .line 21
    .line 22
    return-object p1

    .line 23
    :cond_0
    instance-of p0, p1, Lcom/google/protobuf/e;

    .line 24
    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    check-cast p1, Lcom/google/protobuf/e;

    .line 28
    .line 29
    sget-object p0, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 30
    .line 31
    invoke-virtual {p1}, Lcom/google/protobuf/e;->size()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-nez v0, :cond_1

    .line 36
    .line 37
    const-string p0, ""

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_1
    new-instance v0, Ljava/lang/String;

    .line 41
    .line 42
    iget-object v1, p1, Lcom/google/protobuf/e;->e:[B

    .line 43
    .line 44
    invoke-virtual {p1}, Lcom/google/protobuf/e;->g()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    invoke-virtual {p1}, Lcom/google/protobuf/e;->size()I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    invoke-direct {v0, v1, v2, p1, p0}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 53
    .line 54
    .line 55
    return-object v0

    .line 56
    :cond_2
    check-cast p1, [B

    .line 57
    .line 58
    new-instance p0, Ljava/lang/String;

    .line 59
    .line 60
    sget-object v0, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 61
    .line 62
    invoke-direct {p0, p1, v0}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 63
    .line 64
    .line 65
    return-object p0
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p2, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/protobuf/b;->c()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    instance-of p1, p0, Ljava/lang/String;

    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    check-cast p0, Ljava/lang/String;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    instance-of p1, p0, Lcom/google/protobuf/e;

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    check-cast p0, Lcom/google/protobuf/e;

    .line 24
    .line 25
    sget-object p1, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 26
    .line 27
    invoke-virtual {p0}, Lcom/google/protobuf/e;->size()I

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-nez p2, :cond_1

    .line 32
    .line 33
    const-string p0, ""

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_1
    new-instance p2, Ljava/lang/String;

    .line 37
    .line 38
    iget-object v0, p0, Lcom/google/protobuf/e;->e:[B

    .line 39
    .line 40
    invoke-virtual {p0}, Lcom/google/protobuf/e;->g()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    invoke-virtual {p0}, Lcom/google/protobuf/e;->size()I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    invoke-direct {p2, v0, v1, p0, p1}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 49
    .line 50
    .line 51
    return-object p2

    .line 52
    :cond_2
    check-cast p0, [B

    .line 53
    .line 54
    new-instance p1, Ljava/lang/String;

    .line 55
    .line 56
    sget-object p2, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 57
    .line 58
    invoke-direct {p1, p0, p2}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 59
    .line 60
    .line 61
    return-object p1
.end method

.method public final size()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/y;->e:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

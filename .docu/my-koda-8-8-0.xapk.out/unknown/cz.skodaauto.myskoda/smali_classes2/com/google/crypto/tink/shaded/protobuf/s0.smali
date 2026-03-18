.class public final Lcom/google/crypto/tink/shaded/protobuf/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/crypto/tink/shaded/protobuf/a1;


# instance fields
.field public final a:Lcom/google/crypto/tink/shaded/protobuf/a;

.field public final b:Lcom/google/crypto/tink/shaded/protobuf/d1;

.field public final c:Lcom/google/crypto/tink/shaded/protobuf/q;


# direct methods
.method public constructor <init>(Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->c:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 10
    .line 11
    iput-object p3, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->a:Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-object v0, p1

    .line 7
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 8
    .line 9
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    iput-boolean v1, v0, Lcom/google/crypto/tink/shaded/protobuf/c1;->e:Z

    .line 13
    .line 14
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->c:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    throw p0
.end method

.method public final b(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->c:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    throw p0
.end method

.method public final c()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->a:Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 2
    .line 3
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 4
    .line 5
    const/4 v0, 0x5

    .line 6
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->b()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public final d(Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->c:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    throw p0
.end method

.method public final e(Ljava/lang/Object;[BIILcom/google/crypto/tink/shaded/protobuf/d;)V
    .locals 0

    .line 1
    move-object p0, p1

    .line 2
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 3
    .line 4
    iget-object p2, p0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 5
    .line 6
    sget-object p3, Lcom/google/crypto/tink/shaded/protobuf/c1;->f:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 7
    .line 8
    if-ne p2, p3, :cond_0

    .line 9
    .line 10
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c1;->b()Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    iput-object p2, p0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 15
    .line 16
    :cond_0
    invoke-static {p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    throw p0
.end method

.method public final f(Ljava/lang/Object;Landroidx/collection/h;Lcom/google/crypto/tink/shaded/protobuf/p;)V
    .locals 1

    .line 1
    iget-object p2, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-object p2, p1

    .line 7
    check-cast p2, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 8
    .line 9
    iget-object p3, p2, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 10
    .line 11
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/c1;->f:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 12
    .line 13
    if-ne p3, v0, :cond_0

    .line 14
    .line 15
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c1;->b()Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 16
    .line 17
    .line 18
    move-result-object p3

    .line 19
    iput-object p3, p2, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 20
    .line 21
    :cond_0
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->c:Lcom/google/crypto/tink/shaded/protobuf/q;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    new-instance p0, Ljava/lang/ClassCastException;

    .line 30
    .line 31
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public final g(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/x;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 7
    .line 8
    iget-object p1, p2, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/c1;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    return p0

    .line 18
    :cond_0
    const/4 p0, 0x1

    .line 19
    return p0
.end method

.method public final h(Lcom/google/crypto/tink/shaded/protobuf/x;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/c1;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final i(Lcom/google/crypto/tink/shaded/protobuf/a;)I
    .locals 6

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 7
    .line 8
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 9
    .line 10
    iget p1, p0, Lcom/google/crypto/tink/shaded/protobuf/c1;->d:I

    .line 11
    .line 12
    const/4 v0, -0x1

    .line 13
    if-eq p1, v0, :cond_0

    .line 14
    .line 15
    return p1

    .line 16
    :cond_0
    const/4 p1, 0x0

    .line 17
    move v0, p1

    .line 18
    :goto_0
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/c1;->a:I

    .line 19
    .line 20
    if-ge p1, v1, :cond_1

    .line 21
    .line 22
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/c1;->b:[I

    .line 23
    .line 24
    aget v1, v1, p1

    .line 25
    .line 26
    const/4 v2, 0x3

    .line 27
    ushr-int/2addr v1, v2

    .line 28
    iget-object v3, p0, Lcom/google/crypto/tink/shaded/protobuf/c1;->c:[Ljava/lang/Object;

    .line 29
    .line 30
    aget-object v3, v3, p1

    .line 31
    .line 32
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 33
    .line 34
    const/4 v4, 0x1

    .line 35
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    const/4 v5, 0x2

    .line 40
    mul-int/2addr v4, v5

    .line 41
    invoke-static {v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    invoke-static {v1}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    add-int/2addr v1, v5

    .line 50
    add-int/2addr v1, v4

    .line 51
    invoke-static {v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->z(ILcom/google/crypto/tink/shaded/protobuf/i;)I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    add-int/2addr v2, v1

    .line 56
    add-int/2addr v0, v2

    .line 57
    add-int/lit8 p1, p1, 0x1

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_1
    iput v0, p0, Lcom/google/crypto/tink/shaded/protobuf/c1;->d:I

    .line 61
    .line 62
    return v0
.end method

.method public final j(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/x;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/s0;->b:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 2
    .line 3
    invoke-static {p0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/b1;->x(Lcom/google/crypto/tink/shaded/protobuf/d1;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

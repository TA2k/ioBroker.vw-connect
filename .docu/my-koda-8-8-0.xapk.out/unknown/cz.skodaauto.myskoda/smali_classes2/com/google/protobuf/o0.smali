.class public final Lcom/google/protobuf/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/protobuf/w0;


# instance fields
.field public final a:Lcom/google/protobuf/a;

.field public final b:Lcom/google/protobuf/e1;

.field public final c:Lcom/google/protobuf/i;


# direct methods
.method public constructor <init>(Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/protobuf/o0;->b:Lcom/google/protobuf/e1;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lcom/google/protobuf/o0;->c:Lcom/google/protobuf/i;

    .line 10
    .line 11
    iput-object p3, p0, Lcom/google/protobuf/o0;->a:Lcom/google/protobuf/a;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/o0;->b:Lcom/google/protobuf/e1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-object v0, p1

    .line 7
    check-cast v0, Lcom/google/protobuf/p;

    .line 8
    .line 9
    iget-object v0, v0, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 10
    .line 11
    iget-boolean v1, v0, Lcom/google/protobuf/d1;->e:Z

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    iput-boolean v1, v0, Lcom/google/protobuf/d1;->e:Z

    .line 17
    .line 18
    :cond_0
    iget-object p0, p0, Lcom/google/protobuf/o0;->c:Lcom/google/protobuf/i;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    invoke-static {p1}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    throw p0
.end method

.method public final b(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/o0;->c:Lcom/google/protobuf/i;

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

.method public final c()Lcom/google/protobuf/p;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/o0;->a:Lcom/google/protobuf/a;

    .line 2
    .line 3
    instance-of v0, p0, Lcom/google/protobuf/p;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Lcom/google/protobuf/p;

    .line 8
    .line 9
    const/4 v0, 0x4

    .line 10
    invoke-virtual {p0, v0}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lcom/google/protobuf/p;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    check-cast p0, Lcom/google/protobuf/p;

    .line 18
    .line 19
    const/4 v0, 0x5

    .line 20
    invoke-virtual {p0, v0}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Lcom/google/protobuf/n;

    .line 25
    .line 26
    invoke-virtual {p0}, Lcom/google/protobuf/n;->i()Lcom/google/protobuf/p;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final d(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/o0;->b:Lcom/google/protobuf/e1;

    .line 2
    .line 3
    invoke-static {p0, p1, p2}, Lcom/google/protobuf/x0;->j(Lcom/google/protobuf/e1;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final e(Ljava/lang/Object;Lcom/google/protobuf/f0;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/o0;->c:Lcom/google/protobuf/i;

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

.method public final f(Lcom/google/protobuf/p;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/o0;->b:Lcom/google/protobuf/e1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/google/protobuf/d1;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final g(Lcom/google/protobuf/p;)I
    .locals 6

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/o0;->b:Lcom/google/protobuf/e1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 7
    .line 8
    iget p1, p0, Lcom/google/protobuf/d1;->d:I

    .line 9
    .line 10
    const/4 v0, -0x1

    .line 11
    if-eq p1, v0, :cond_0

    .line 12
    .line 13
    return p1

    .line 14
    :cond_0
    const/4 p1, 0x0

    .line 15
    move v0, p1

    .line 16
    :goto_0
    iget v1, p0, Lcom/google/protobuf/d1;->a:I

    .line 17
    .line 18
    if-ge p1, v1, :cond_1

    .line 19
    .line 20
    iget-object v1, p0, Lcom/google/protobuf/d1;->b:[I

    .line 21
    .line 22
    aget v1, v1, p1

    .line 23
    .line 24
    const/4 v2, 0x3

    .line 25
    ushr-int/2addr v1, v2

    .line 26
    iget-object v3, p0, Lcom/google/protobuf/d1;->c:[Ljava/lang/Object;

    .line 27
    .line 28
    aget-object v3, v3, p1

    .line 29
    .line 30
    check-cast v3, Lcom/google/protobuf/e;

    .line 31
    .line 32
    const/4 v4, 0x1

    .line 33
    invoke-static {v4}, Lcom/google/protobuf/f;->f(I)I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    const/4 v5, 0x2

    .line 38
    mul-int/2addr v4, v5

    .line 39
    invoke-static {v5}, Lcom/google/protobuf/f;->f(I)I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    invoke-static {v1}, Lcom/google/protobuf/f;->g(I)I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    add-int/2addr v1, v5

    .line 48
    add-int/2addr v1, v4

    .line 49
    invoke-static {v2}, Lcom/google/protobuf/f;->f(I)I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    invoke-virtual {v3}, Lcom/google/protobuf/e;->size()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    add-int/2addr v4, v3

    .line 62
    add-int/2addr v4, v2

    .line 63
    add-int/2addr v4, v1

    .line 64
    add-int/2addr v0, v4

    .line 65
    add-int/lit8 p1, p1, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    iput v0, p0, Lcom/google/protobuf/d1;->d:I

    .line 69
    .line 70
    return v0
.end method

.method public final h(Lcom/google/protobuf/p;Lcom/google/protobuf/p;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/protobuf/o0;->b:Lcom/google/protobuf/e1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 7
    .line 8
    iget-object p1, p2, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lcom/google/protobuf/d1;->equals(Ljava/lang/Object;)Z

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

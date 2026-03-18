.class public abstract Lcom/google/crypto/tink/shaded/protobuf/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Cloneable;


# instance fields
.field public final d:Lcom/google/crypto/tink/shaded/protobuf/x;

.field public e:Lcom/google/crypto/tink/shaded/protobuf/x;

.field public f:Z


# direct methods
.method public constructor <init>(Lcom/google/crypto/tink/shaded/protobuf/x;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->d:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 5
    .line 6
    const/4 v0, 0x4

    .line 7
    invoke-virtual {p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 12
    .line 13
    iput-object p1, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 14
    .line 15
    const/4 p1, 0x0

    .line 16
    iput-boolean p1, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->f:Z

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()Lcom/google/crypto/tink/shaded/protobuf/x;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->b()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/x;->i()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, La8/r0;

    .line 13
    .line 14
    invoke-direct {p0}, La8/r0;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final b()Lcom/google/crypto/tink/shaded/protobuf/x;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-virtual {v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-interface {v1, v0}, Lcom/google/crypto/tink/shaded/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    const/4 v0, 0x1

    .line 30
    iput-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->f:Z

    .line 31
    .line 32
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 33
    .line 34
    return-object p0
.end method

.method public final c()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 6
    .line 7
    const/4 v1, 0x4

    .line 8
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 13
    .line 14
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 15
    .line 16
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-interface {v2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->j(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    iput-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->f:Z

    .line 36
    .line 37
    :cond_0
    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->d:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->b()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {v0, p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->d(Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final d(Lcom/google/crypto/tink/shaded/protobuf/x;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 5
    .line 6
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-interface {v0, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->j(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

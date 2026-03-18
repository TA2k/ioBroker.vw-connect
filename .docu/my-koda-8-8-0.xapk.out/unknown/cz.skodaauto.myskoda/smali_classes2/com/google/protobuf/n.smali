.class public abstract Lcom/google/protobuf/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Cloneable;


# instance fields
.field public final d:Lcom/google/protobuf/p;

.field public e:Lcom/google/protobuf/p;


# direct methods
.method public constructor <init>(Lcom/google/protobuf/p;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/protobuf/n;->d:Lcom/google/protobuf/p;

    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/google/protobuf/p;->n()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    invoke-virtual {p1, v0}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Lcom/google/protobuf/p;

    .line 18
    .line 19
    iput-object p1, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 23
    .line 24
    const-string p1, "Default instance must be immutable."

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0
.end method


# virtual methods
.method public final clone()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/n;->d:Lcom/google/protobuf/p;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-virtual {v0, v1}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Lcom/google/protobuf/n;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/protobuf/n;->i()Lcom/google/protobuf/p;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iput-object p0, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 15
    .line 16
    return-object v0
.end method

.method public final h()Lcom/google/protobuf/p;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/protobuf/n;->i()Lcom/google/protobuf/p;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    invoke-virtual {p0, v0}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Ljava/lang/Byte;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/Byte;->byteValue()B

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-ne v1, v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    if-nez v1, :cond_1

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    sget-object v0, Lcom/google/protobuf/t0;->c:Lcom/google/protobuf/t0;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v0, v1}, Lcom/google/protobuf/t0;->a(Ljava/lang/Class;)Lcom/google/protobuf/w0;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-interface {v0, p0}, Lcom/google/protobuf/w0;->b(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    const/4 v1, 0x2

    .line 44
    invoke-virtual {p0, v1}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    :goto_0
    if-eqz v0, :cond_2

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_2
    new-instance p0, La8/r0;

    .line 51
    .line 52
    const-string v0, "Message was missing required fields.  (Lite runtime could not determine which fields were missing)."

    .line 53
    .line 54
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0
.end method

.method public final i()Lcom/google/protobuf/p;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/protobuf/p;->n()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object v0, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    sget-object v1, Lcom/google/protobuf/t0;->c:Lcom/google/protobuf/t0;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v1, v2}, Lcom/google/protobuf/t0;->a(Ljava/lang/Class;)Lcom/google/protobuf/w0;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-interface {v1, v0}, Lcom/google/protobuf/w0;->a(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Lcom/google/protobuf/p;->o()V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 37
    .line 38
    return-object p0
.end method

.method public final j()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/protobuf/p;->n()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/protobuf/n;->d:Lcom/google/protobuf/p;

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    invoke-virtual {v0, v1}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lcom/google/protobuf/p;

    .line 17
    .line 18
    iget-object v1, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 19
    .line 20
    sget-object v2, Lcom/google/protobuf/t0;->c:Lcom/google/protobuf/t0;

    .line 21
    .line 22
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    invoke-virtual {v2, v3}, Lcom/google/protobuf/t0;->a(Ljava/lang/Class;)Lcom/google/protobuf/w0;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-interface {v2, v0, v1}, Lcom/google/protobuf/w0;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 37
    .line 38
    :cond_0
    return-void
.end method

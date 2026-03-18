.class public abstract Lcom/google/android/gms/internal/measurement/k5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Cloneable;


# instance fields
.field public final d:Lcom/google/android/gms/internal/measurement/l5;

.field public e:Lcom/google/android/gms/internal/measurement/l5;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/l5;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/k5;->d:Lcom/google/android/gms/internal/measurement/l5;

    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/l5;->e()Z

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
    invoke-virtual {p1, v0}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Lcom/google/android/gms/internal/measurement/l5;

    .line 18
    .line 19
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

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

.method public static a(ILjava/util/List;)V
    .locals 3

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sub-int/2addr v0, p0

    .line 6
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    new-instance v2, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    add-int/lit8 v1, v1, 0x1a

    .line 17
    .line 18
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 19
    .line 20
    .line 21
    const-string v1, "Element at index "

    .line 22
    .line 23
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v0, " is null."

    .line 30
    .line 31
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    :goto_0
    add-int/lit8 v1, v1, -0x1

    .line 43
    .line 44
    if-lt v1, p0, :cond_0

    .line 45
    .line 46
    invoke-interface {p1, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 51
    .line 52
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0
.end method


# virtual methods
.method public final b()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->e()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->d:Lcom/google/android/gms/internal/measurement/l5;

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lcom/google/android/gms/internal/measurement/l5;

    .line 17
    .line 18
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 19
    .line 20
    sget-object v2, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-virtual {v2, v3}, Lcom/google/android/gms/internal/measurement/k6;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/n6;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-interface {v2, v0, v1}, Lcom/google/android/gms/internal/measurement/n6;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 34
    .line 35
    :cond_0
    return-void
.end method

.method public final c()Lcom/google/android/gms/internal/measurement/k5;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->d:Lcom/google/android/gms/internal/measurement/l5;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Lcom/google/android/gms/internal/measurement/k5;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/k5;->d()Lcom/google/android/gms/internal/measurement/l5;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iput-object p0, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 15
    .line 16
    return-object v0
.end method

.method public final bridge synthetic clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/k5;->c()Lcom/google/android/gms/internal/measurement/k5;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d()Lcom/google/android/gms/internal/measurement/l5;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->e()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 13
    .line 14
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->g()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 18
    .line 19
    return-object p0
.end method

.method public final e()Lcom/google/android/gms/internal/measurement/l5;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/k5;->d()Lcom/google/android/gms/internal/measurement/l5;

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
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

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
    sget-object v0, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/k6;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/n6;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-interface {v0, p0}, Lcom/google/android/gms/internal/measurement/n6;->a(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v1, 0x2

    .line 41
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    :goto_0
    if-eqz v0, :cond_2

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_2
    new-instance p0, La8/r0;

    .line 48
    .line 49
    const-string v0, "Message was missing required fields.  (Lite runtime could not determine which fields were missing)."

    .line 50
    .line 51
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0
.end method

.method public final f(Lcom/google/android/gms/internal/measurement/l5;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->d:Lcom/google/android/gms/internal/measurement/l5;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lcom/google/android/gms/internal/measurement/l5;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/l5;->e()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x4

    .line 18
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lcom/google/android/gms/internal/measurement/l5;

    .line 23
    .line 24
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 25
    .line 26
    sget-object v2, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-virtual {v2, v3}, Lcom/google/android/gms/internal/measurement/k6;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/n6;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-interface {v2, v0, v1}, Lcom/google/android/gms/internal/measurement/n6;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 40
    .line 41
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 42
    .line 43
    sget-object v0, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/k6;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/n6;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-interface {v0, p0, p1}, Lcom/google/android/gms/internal/measurement/n6;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_1
    return-void
.end method

.method public final h([BILcom/google/android/gms/internal/measurement/d5;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->e()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->d:Lcom/google/android/gms/internal/measurement/l5;

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/l5;->o(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lcom/google/android/gms/internal/measurement/l5;

    .line 17
    .line 18
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 19
    .line 20
    sget-object v2, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-virtual {v2, v3}, Lcom/google/android/gms/internal/measurement/k6;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/n6;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-interface {v2, v0, v1}, Lcom/google/android/gms/internal/measurement/n6;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 34
    .line 35
    :cond_0
    :try_start_0
    sget-object v0, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 36
    .line 37
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/k6;->a(Ljava/lang/Class;)Lcom/google/android/gms/internal/measurement/n6;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    iget-object v3, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 48
    .line 49
    new-instance v7, Lcom/google/android/gms/internal/measurement/w4;

    .line 50
    .line 51
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    const/4 v5, 0x0

    .line 58
    move-object v4, p1

    .line 59
    move v6, p2

    .line 60
    invoke-interface/range {v2 .. v7}, Lcom/google/android/gms/internal/measurement/n6;->g(Ljava/lang/Object;[BIILcom/google/android/gms/internal/measurement/w4;)V
    :try_end_0
    .catch Lcom/google/android/gms/internal/measurement/u5; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :catch_0
    move-exception v0

    .line 65
    move-object p0, v0

    .line 66
    new-instance p1, Ljava/lang/RuntimeException;

    .line 67
    .line 68
    const-string p2, "Reading from byte array should not throw IOException."

    .line 69
    .line 70
    invoke-direct {p1, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 71
    .line 72
    .line 73
    throw p1

    .line 74
    :catch_1
    new-instance p0, Lcom/google/android/gms/internal/measurement/u5;

    .line 75
    .line 76
    const-string p1, "While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length."

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :catch_2
    move-exception v0

    .line 83
    move-object p0, v0

    .line 84
    throw p0
.end method

.class public abstract Lmo/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lcom/google/android/gms/common/data/DataHolder;

.field public final e:I

.field public final f:I


# direct methods
.method public constructor <init>(Lcom/google/android/gms/common/data/DataHolder;I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-ltz p2, :cond_0

    .line 11
    .line 12
    iget v1, p1, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 13
    .line 14
    if-ge p2, v1, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    :cond_0
    invoke-static {v0}, Lno/c0;->k(Z)V

    .line 18
    .line 19
    .line 20
    iput p2, p0, Lmo/b;->e:I

    .line 21
    .line 22
    invoke-virtual {p1, p2}, Lcom/google/android/gms/common/data/DataHolder;->x0(I)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    iput p1, p0, Lmo/b;->f:I

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a()[B
    .locals 4

    .line 1
    iget-object v0, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 2
    .line 3
    iget v1, p0, Lmo/b;->e:I

    .line 4
    .line 5
    const-string v2, "data"

    .line 6
    .line 7
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v3, v0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 11
    .line 12
    iget p0, p0, Lmo/b;->f:I

    .line 13
    .line 14
    aget-object p0, v3, p0

    .line 15
    .line 16
    iget-object v0, v0, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 17
    .line 18
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-virtual {p0, v1, v0}, Landroid/database/CursorWindow;->getBlob(II)[B

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lmo/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    check-cast p1, Lmo/b;

    .line 7
    .line 8
    iget v0, p1, Lmo/b;->e:I

    .line 9
    .line 10
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget v2, p0, Lmo/b;->e:I

    .line 15
    .line 16
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    iget v0, p1, Lmo/b;->f:I

    .line 27
    .line 28
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iget v2, p0, Lmo/b;->f:I

    .line 33
    .line 34
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-static {v0, v2}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_0

    .line 43
    .line 44
    iget-object p1, p1, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 45
    .line 46
    iget-object p0, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 47
    .line 48
    if-ne p1, p0, :cond_0

    .line 49
    .line 50
    const/4 p0, 0x1

    .line 51
    return p0

    .line 52
    :cond_0
    return v1
.end method

.method public getData()[B
    .locals 0

    .line 1
    invoke-virtual {p0}, Lmo/b;->a()[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Lmo/b;->e:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v1, p0, Lmo/b;->f:I

    .line 8
    .line 9
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object p0, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 14
    .line 15
    filled-new-array {v0, v1, p0}, [Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method

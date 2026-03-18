.class public final Lcq/q;
.super Lmo/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbq/c;


# virtual methods
.method public final getId()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 2
    .line 3
    iget v1, p0, Lmo/b;->e:I

    .line 4
    .line 5
    const-string v2, "asset_id"

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
    invoke-virtual {p0, v1, v0}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final k()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 2
    .line 3
    iget v1, p0, Lmo/b;->e:I

    .line 4
    .line 5
    const-string v2, "asset_key"

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
    invoke-virtual {p0, v1, v0}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

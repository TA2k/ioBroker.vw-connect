.class public final Lcq/p;
.super Lmo/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:I


# direct methods
.method public constructor <init>(Lcom/google/android/gms/common/data/DataHolder;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lmo/b;-><init>(Lcom/google/android/gms/common/data/DataHolder;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcq/p;->g:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 2
    .line 3
    iget v1, p0, Lmo/b;->e:I

    .line 4
    .line 5
    const-string v2, "event_type"

    .line 6
    .line 7
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v3, v0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 11
    .line 12
    iget v4, p0, Lmo/b;->f:I

    .line 13
    .line 14
    aget-object v3, v3, v4

    .line 15
    .line 16
    iget-object v4, v0, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 17
    .line 18
    invoke-virtual {v4, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    invoke-virtual {v3, v1, v4}, Landroid/database/CursorWindow;->getInt(II)I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    const/4 v3, 0x1

    .line 27
    if-ne v1, v3, :cond_0

    .line 28
    .line 29
    const-string v1, "changed"

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget v1, p0, Lmo/b;->e:I

    .line 33
    .line 34
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object v3, v0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 38
    .line 39
    iget v4, p0, Lmo/b;->f:I

    .line 40
    .line 41
    aget-object v3, v3, v4

    .line 42
    .line 43
    iget-object v4, v0, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 44
    .line 45
    invoke-virtual {v4, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    invoke-virtual {v3, v1, v2}, Landroid/database/CursorWindow;->getInt(II)I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    const/4 v2, 0x2

    .line 54
    if-ne v1, v2, :cond_1

    .line 55
    .line 56
    const-string v1, "deleted"

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_1
    const-string v1, "unknown"

    .line 60
    .line 61
    :goto_0
    new-instance v2, Lcq/s;

    .line 62
    .line 63
    iget v3, p0, Lmo/b;->e:I

    .line 64
    .line 65
    iget p0, p0, Lcq/p;->g:I

    .line 66
    .line 67
    invoke-direct {v2, v0, v3, p0}, Lcq/s;-><init>(Lcom/google/android/gms/common/data/DataHolder;II)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v2}, Lcq/s;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    const-string v0, ", dataitem="

    .line 75
    .line 76
    const-string v2, " }"

    .line 77
    .line 78
    const-string v3, "DataEventRef{ type="

    .line 79
    .line 80
    invoke-static {v3, v1, v0, p0, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0
.end method

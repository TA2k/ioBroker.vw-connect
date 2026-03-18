.class public abstract Lmo/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Ljava/io/Closeable;


# instance fields
.field public final d:Lcom/google/android/gms/common/data/DataHolder;

.field public e:Z

.field public f:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/common/data/DataHolder;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-boolean p1, p0, Lmo/c;->e:Z

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final B()V
    .locals 8

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lmo/c;->e:Z

    .line 3
    .line 4
    if-nez v0, :cond_3

    .line 5
    .line 6
    iget-object v0, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 7
    .line 8
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget v0, v0, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 12
    .line 13
    new-instance v1, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    if-lez v0, :cond_2

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    const-string v1, "path"

    .line 32
    .line 33
    iget-object v4, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 34
    .line 35
    invoke-virtual {v4, v3}, Lcom/google/android/gms/common/data/DataHolder;->x0(I)I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    iget-object v5, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 40
    .line 41
    invoke-virtual {v5, v3, v1}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object v6, v5, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 45
    .line 46
    aget-object v4, v6, v4

    .line 47
    .line 48
    iget-object v5, v5, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 49
    .line 50
    invoke-virtual {v5, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    invoke-virtual {v4, v3, v5}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    move v4, v2

    .line 59
    :goto_0
    if-ge v4, v0, :cond_2

    .line 60
    .line 61
    iget-object v5, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 62
    .line 63
    invoke-virtual {v5, v4}, Lcom/google/android/gms/common/data/DataHolder;->x0(I)I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    iget-object v6, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 68
    .line 69
    invoke-virtual {v6, v4, v1}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object v7, v6, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 73
    .line 74
    aget-object v7, v7, v5

    .line 75
    .line 76
    iget-object v6, v6, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 77
    .line 78
    invoke-virtual {v6, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 79
    .line 80
    .line 81
    move-result v6

    .line 82
    invoke-virtual {v7, v4, v6}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    if-eqz v6, :cond_1

    .line 87
    .line 88
    invoke-virtual {v6, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v5

    .line 92
    if-nez v5, :cond_0

    .line 93
    .line 94
    iget-object v3, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 97
    .line 98
    .line 99
    move-result-object v5

    .line 100
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-object v3, v6

    .line 104
    goto :goto_1

    .line 105
    :catchall_0
    move-exception v0

    .line 106
    goto :goto_2

    .line 107
    :cond_0
    :goto_1
    add-int/lit8 v4, v4, 0x1

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_1
    new-instance v0, Ljava/lang/NullPointerException;

    .line 111
    .line 112
    new-instance v2, Ljava/lang/StringBuilder;

    .line 113
    .line 114
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 115
    .line 116
    .line 117
    const-string v3, "Missing value for markerColumn: "

    .line 118
    .line 119
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    const-string v1, ", at row: "

    .line 126
    .line 127
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v1, ", for window: "

    .line 134
    .line 135
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw v0

    .line 149
    :cond_2
    iput-boolean v2, p0, Lmo/c;->e:Z

    .line 150
    .line 151
    :cond_3
    monitor-exit p0

    .line 152
    return-void

    .line 153
    :goto_2
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 154
    throw v0
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public abstract g(II)Ljava/lang/Object;
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lmo/a;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lmo/a;-><init>(Lmo/c;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final k(I)I
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-ge p1, v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 25
    .line 26
    const-string v0, "Position "

    .line 27
    .line 28
    const-string v1, " is out of bounds for this buffer"

    .line 29
    .line 30
    invoke-static {v0, p1, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

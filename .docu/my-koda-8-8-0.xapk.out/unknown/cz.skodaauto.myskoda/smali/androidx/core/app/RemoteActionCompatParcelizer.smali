.class public Landroidx/core/app/RemoteActionCompatParcelizer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static read(Ldb/a;)Landroidx/core/app/RemoteActionCompat;
    .locals 5

    .line 1
    new-instance v0, Landroidx/core/app/RemoteActionCompat;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/core/app/RemoteActionCompat;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, v0, Landroidx/core/app/RemoteActionCompat;->a:Landroidx/core/graphics/drawable/IconCompat;

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-virtual {p0, v2}, Ldb/a;->e(I)Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Ldb/a;->g()Ldb/c;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    :goto_0
    check-cast v1, Landroidx/core/graphics/drawable/IconCompat;

    .line 21
    .line 22
    iput-object v1, v0, Landroidx/core/app/RemoteActionCompat;->a:Landroidx/core/graphics/drawable/IconCompat;

    .line 23
    .line 24
    iget-object v1, v0, Landroidx/core/app/RemoteActionCompat;->b:Ljava/lang/CharSequence;

    .line 25
    .line 26
    const/4 v3, 0x2

    .line 27
    invoke-virtual {p0, v3}, Ldb/a;->e(I)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move-object v1, p0

    .line 35
    check-cast v1, Ldb/b;

    .line 36
    .line 37
    sget-object v3, Landroid/text/TextUtils;->CHAR_SEQUENCE_CREATOR:Landroid/os/Parcelable$Creator;

    .line 38
    .line 39
    iget-object v1, v1, Ldb/b;->e:Landroid/os/Parcel;

    .line 40
    .line 41
    invoke-interface {v3, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    check-cast v1, Ljava/lang/CharSequence;

    .line 46
    .line 47
    :goto_1
    iput-object v1, v0, Landroidx/core/app/RemoteActionCompat;->b:Ljava/lang/CharSequence;

    .line 48
    .line 49
    iget-object v1, v0, Landroidx/core/app/RemoteActionCompat;->c:Ljava/lang/CharSequence;

    .line 50
    .line 51
    const/4 v3, 0x3

    .line 52
    invoke-virtual {p0, v3}, Ldb/a;->e(I)Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-nez v3, :cond_2

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_2
    move-object v1, p0

    .line 60
    check-cast v1, Ldb/b;

    .line 61
    .line 62
    sget-object v3, Landroid/text/TextUtils;->CHAR_SEQUENCE_CREATOR:Landroid/os/Parcelable$Creator;

    .line 63
    .line 64
    iget-object v1, v1, Ldb/b;->e:Landroid/os/Parcel;

    .line 65
    .line 66
    invoke-interface {v3, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Ljava/lang/CharSequence;

    .line 71
    .line 72
    :goto_2
    iput-object v1, v0, Landroidx/core/app/RemoteActionCompat;->c:Ljava/lang/CharSequence;

    .line 73
    .line 74
    iget-object v1, v0, Landroidx/core/app/RemoteActionCompat;->d:Landroid/app/PendingIntent;

    .line 75
    .line 76
    const/4 v3, 0x4

    .line 77
    invoke-virtual {p0, v1, v3}, Ldb/a;->f(Landroid/os/Parcelable;I)Landroid/os/Parcelable;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    check-cast v1, Landroid/app/PendingIntent;

    .line 82
    .line 83
    iput-object v1, v0, Landroidx/core/app/RemoteActionCompat;->d:Landroid/app/PendingIntent;

    .line 84
    .line 85
    iget-boolean v1, v0, Landroidx/core/app/RemoteActionCompat;->e:Z

    .line 86
    .line 87
    const/4 v3, 0x5

    .line 88
    invoke-virtual {p0, v3}, Ldb/a;->e(I)Z

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    const/4 v4, 0x0

    .line 93
    if-nez v3, :cond_3

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_3
    move-object v1, p0

    .line 97
    check-cast v1, Ldb/b;

    .line 98
    .line 99
    iget-object v1, v1, Ldb/b;->e:Landroid/os/Parcel;

    .line 100
    .line 101
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-eqz v1, :cond_4

    .line 106
    .line 107
    move v1, v2

    .line 108
    goto :goto_3

    .line 109
    :cond_4
    move v1, v4

    .line 110
    :goto_3
    iput-boolean v1, v0, Landroidx/core/app/RemoteActionCompat;->e:Z

    .line 111
    .line 112
    iget-boolean v1, v0, Landroidx/core/app/RemoteActionCompat;->f:Z

    .line 113
    .line 114
    const/4 v3, 0x6

    .line 115
    invoke-virtual {p0, v3}, Ldb/a;->e(I)Z

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    if-nez v3, :cond_5

    .line 120
    .line 121
    move v2, v1

    .line 122
    goto :goto_4

    .line 123
    :cond_5
    check-cast p0, Ldb/b;

    .line 124
    .line 125
    iget-object p0, p0, Ldb/b;->e:Landroid/os/Parcel;

    .line 126
    .line 127
    invoke-virtual {p0}, Landroid/os/Parcel;->readInt()I

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-eqz p0, :cond_6

    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_6
    move v2, v4

    .line 135
    :goto_4
    iput-boolean v2, v0, Landroidx/core/app/RemoteActionCompat;->f:Z

    .line 136
    .line 137
    return-object v0
.end method

.method public static write(Landroidx/core/app/RemoteActionCompat;Ldb/a;)V
    .locals 4

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Landroidx/core/app/RemoteActionCompat;->a:Landroidx/core/graphics/drawable/IconCompat;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-virtual {p1, v1}, Ldb/a;->h(I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1, v0}, Ldb/a;->i(Ldb/c;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Landroidx/core/app/RemoteActionCompat;->b:Ljava/lang/CharSequence;

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    invoke-virtual {p1, v1}, Ldb/a;->h(I)V

    .line 17
    .line 18
    .line 19
    move-object v1, p1

    .line 20
    check-cast v1, Ldb/b;

    .line 21
    .line 22
    iget-object v1, v1, Ldb/b;->e:Landroid/os/Parcel;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    invoke-static {v0, v1, v2}, Landroid/text/TextUtils;->writeToParcel(Ljava/lang/CharSequence;Landroid/os/Parcel;I)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Landroidx/core/app/RemoteActionCompat;->c:Ljava/lang/CharSequence;

    .line 29
    .line 30
    const/4 v3, 0x3

    .line 31
    invoke-virtual {p1, v3}, Ldb/a;->h(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {v0, v1, v2}, Landroid/text/TextUtils;->writeToParcel(Ljava/lang/CharSequence;Landroid/os/Parcel;I)V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Landroidx/core/app/RemoteActionCompat;->d:Landroid/app/PendingIntent;

    .line 38
    .line 39
    const/4 v3, 0x4

    .line 40
    invoke-virtual {p1, v3}, Ldb/a;->h(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v0, v2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 44
    .line 45
    .line 46
    iget-boolean v0, p0, Landroidx/core/app/RemoteActionCompat;->e:Z

    .line 47
    .line 48
    const/4 v2, 0x5

    .line 49
    invoke-virtual {p1, v2}, Ldb/a;->h(I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 53
    .line 54
    .line 55
    iget-boolean p0, p0, Landroidx/core/app/RemoteActionCompat;->f:Z

    .line 56
    .line 57
    const/4 v0, 0x6

    .line 58
    invoke-virtual {p1, v0}, Ldb/a;->h(I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

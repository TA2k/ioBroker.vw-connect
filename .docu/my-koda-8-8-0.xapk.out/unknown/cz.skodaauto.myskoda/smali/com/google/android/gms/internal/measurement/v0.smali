.class public final Lcom/google/android/gms/internal/measurement/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable$Creator;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/gms/internal/measurement/v0;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/v0;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x0

    .line 11
    const/4 v1, 0x0

    .line 12
    move v2, v1

    .line 13
    move-object v1, v0

    .line 14
    :goto_0
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-ge v3, p0, :cond_3

    .line 19
    .line 20
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    int-to-char v4, v3

    .line 25
    const/4 v5, 0x1

    .line 26
    if-eq v4, v5, :cond_2

    .line 27
    .line 28
    const/4 v5, 0x2

    .line 29
    if-eq v4, v5, :cond_1

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    if-eq v4, v5, :cond_0

    .line 33
    .line 34
    invoke-static {p1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    sget-object v1, Landroid/content/Intent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 39
    .line 40
    invoke-static {p1, v3, v1}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Landroid/content/Intent;

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    invoke-static {p1, v3}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-static {p1, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    goto :goto_0

    .line 57
    :cond_3
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 58
    .line 59
    .line 60
    new-instance p0, Lcom/google/android/gms/internal/measurement/w0;

    .line 61
    .line 62
    invoke-direct {p0, v2, v0, v1}, Lcom/google/android/gms/internal/measurement/w0;-><init>(ILjava/lang/String;Landroid/content/Intent;)V

    .line 63
    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_0
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    const/4 v0, 0x0

    .line 71
    const/4 v1, 0x0

    .line 72
    const-wide/16 v2, 0x0

    .line 73
    .line 74
    move-object v10, v0

    .line 75
    move-object v11, v10

    .line 76
    move v9, v1

    .line 77
    move-wide v5, v2

    .line 78
    move-wide v7, v5

    .line 79
    :goto_1
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    if-ge v0, p0, :cond_9

    .line 84
    .line 85
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    int-to-char v1, v0

    .line 90
    const/4 v2, 0x1

    .line 91
    if-eq v1, v2, :cond_8

    .line 92
    .line 93
    const/4 v2, 0x2

    .line 94
    if-eq v1, v2, :cond_7

    .line 95
    .line 96
    const/4 v2, 0x3

    .line 97
    if-eq v1, v2, :cond_6

    .line 98
    .line 99
    const/4 v2, 0x7

    .line 100
    if-eq v1, v2, :cond_5

    .line 101
    .line 102
    const/16 v2, 0x8

    .line 103
    .line 104
    if-eq v1, v2, :cond_4

    .line 105
    .line 106
    invoke-static {p1, v0}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_4
    invoke-static {p1, v0}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    move-object v11, v0

    .line 115
    goto :goto_1

    .line 116
    :cond_5
    invoke-static {p1, v0}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    move-object v10, v0

    .line 121
    goto :goto_1

    .line 122
    :cond_6
    invoke-static {p1, v0}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    move v9, v0

    .line 127
    goto :goto_1

    .line 128
    :cond_7
    invoke-static {p1, v0}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 129
    .line 130
    .line 131
    move-result-wide v0

    .line 132
    move-wide v7, v0

    .line 133
    goto :goto_1

    .line 134
    :cond_8
    invoke-static {p1, v0}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 135
    .line 136
    .line 137
    move-result-wide v0

    .line 138
    move-wide v5, v0

    .line 139
    goto :goto_1

    .line 140
    :cond_9
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 141
    .line 142
    .line 143
    new-instance v4, Lcom/google/android/gms/internal/measurement/u0;

    .line 144
    .line 145
    invoke-direct/range {v4 .. v11}, Lcom/google/android/gms/internal/measurement/u0;-><init>(JJZLandroid/os/Bundle;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    return-object v4

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final synthetic newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/v0;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lcom/google/android/gms/internal/measurement/w0;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lcom/google/android/gms/internal/measurement/u0;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

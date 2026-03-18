.class public final Lgp/d;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Laq/k;


# direct methods
.method public constructor <init>(ILaq/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lgp/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lgp/d;->e:Laq/k;

    .line 7
    .line 8
    const-string p1, "com.google.android.gms.location.internal.ISettingsCallbacks"

    .line 9
    .line 10
    const/4 p2, 0x5

    .line 11
    invoke-direct {p0, p1, p2}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    iput-object p2, p0, Lgp/d;->e:Laq/k;

    .line 16
    .line 17
    const-string p1, "com.google.android.gms.location.internal.IGeofencerCallbacks"

    .line 18
    .line 19
    const/4 p2, 0x5

    .line 20
    invoke-direct {p0, p1, p2}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final S(Landroid/os/Parcel;I)Z
    .locals 6

    .line 1
    iget v0, p0, Lgp/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/16 v0, 0xd

    .line 7
    .line 8
    const/16 v1, 0x3ee

    .line 9
    .line 10
    const/16 v2, 0x3e8

    .line 11
    .line 12
    iget-object p0, p0, Lgp/d;->e:Laq/k;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x1

    .line 16
    if-eq p2, v4, :cond_6

    .line 17
    .line 18
    const/4 v5, 0x2

    .line 19
    if-eq p2, v5, :cond_3

    .line 20
    .line 21
    const/4 v5, 0x3

    .line 22
    if-eq p2, v5, :cond_0

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    sget-object v5, Landroid/app/PendingIntent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 31
    .line 32
    invoke-static {p1, v5}, Lgp/b;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    check-cast v5, Landroid/app/PendingIntent;

    .line 37
    .line 38
    invoke-static {p1}, Lgp/b;->c(Landroid/os/Parcel;)V

    .line 39
    .line 40
    .line 41
    new-instance p1, Lcom/google/android/gms/common/api/Status;

    .line 42
    .line 43
    if-eqz p2, :cond_1

    .line 44
    .line 45
    if-lt p2, v2, :cond_2

    .line 46
    .line 47
    if-ge p2, v1, :cond_2

    .line 48
    .line 49
    :cond_1
    move v0, p2

    .line 50
    :cond_2
    invoke-direct {p1, v0, v3, v3, v3}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p1, v3, p0}, Llp/yf;->b(Lcom/google/android/gms/common/api/Status;Ljava/lang/Object;Laq/k;)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_3
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    invoke-virtual {p1}, Landroid/os/Parcel;->createStringArray()[Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    invoke-static {p1}, Lgp/b;->c(Landroid/os/Parcel;)V

    .line 65
    .line 66
    .line 67
    new-instance p1, Lcom/google/android/gms/common/api/Status;

    .line 68
    .line 69
    if-eqz p2, :cond_4

    .line 70
    .line 71
    if-lt p2, v2, :cond_5

    .line 72
    .line 73
    if-ge p2, v1, :cond_5

    .line 74
    .line 75
    :cond_4
    move v0, p2

    .line 76
    :cond_5
    invoke-direct {p1, v0, v3, v3, v3}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 77
    .line 78
    .line 79
    invoke-static {p1, v3, p0}, Llp/yf;->b(Lcom/google/android/gms/common/api/Status;Ljava/lang/Object;Laq/k;)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_6
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    invoke-virtual {p1}, Landroid/os/Parcel;->createStringArray()[Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    invoke-static {p1}, Lgp/b;->c(Landroid/os/Parcel;)V

    .line 91
    .line 92
    .line 93
    new-instance p1, Lcom/google/android/gms/common/api/Status;

    .line 94
    .line 95
    if-eqz p2, :cond_7

    .line 96
    .line 97
    if-lt p2, v2, :cond_8

    .line 98
    .line 99
    if-ge p2, v1, :cond_8

    .line 100
    .line 101
    :cond_7
    move v0, p2

    .line 102
    :cond_8
    invoke-direct {p1, v0, v3, v3, v3}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 103
    .line 104
    .line 105
    invoke-static {p1, v3, p0}, Llp/yf;->b(Lcom/google/android/gms/common/api/Status;Ljava/lang/Object;Laq/k;)V

    .line 106
    .line 107
    .line 108
    :goto_0
    return v4

    .line 109
    :pswitch_0
    const/4 v0, 0x1

    .line 110
    if-ne p2, v0, :cond_9

    .line 111
    .line 112
    sget-object p2, Lpp/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 113
    .line 114
    invoke-static {p1, p2}, Lgp/b;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    check-cast p2, Lpp/f;

    .line 119
    .line 120
    invoke-static {p1}, Lgp/b;->c(Landroid/os/Parcel;)V

    .line 121
    .line 122
    .line 123
    iget-object p1, p2, Lpp/f;->d:Lcom/google/android/gms/common/api/Status;

    .line 124
    .line 125
    new-instance p2, Lrb0/a;

    .line 126
    .line 127
    const/16 v1, 0xb

    .line 128
    .line 129
    invoke-direct {p2, v1}, Lrb0/a;-><init>(I)V

    .line 130
    .line 131
    .line 132
    iget-object p0, p0, Lgp/d;->e:Laq/k;

    .line 133
    .line 134
    invoke-static {p1, p2, p0}, Llp/yf;->b(Lcom/google/android/gms/common/api/Status;Ljava/lang/Object;Laq/k;)V

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_9
    const/4 v0, 0x0

    .line 139
    :goto_1
    return v0

    .line 140
    nop

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

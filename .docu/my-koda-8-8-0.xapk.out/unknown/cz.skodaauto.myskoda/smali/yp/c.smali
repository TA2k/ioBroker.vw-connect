.class public abstract Lyp/c;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final Q(ILandroid/os/Parcel;Landroid/os/Parcel;)Z
    .locals 2

    .line 1
    packed-switch p1, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    :pswitch_0
    const/4 p0, 0x0

    .line 5
    return p0

    .line 6
    :pswitch_1
    sget-object p0, Lyp/e;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    invoke-static {p2, p0}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lyp/e;

    .line 13
    .line 14
    invoke-static {p2}, Lcp/a;->b(Landroid/os/Parcel;)V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :pswitch_2
    sget-object p1, Lyp/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 19
    .line 20
    invoke-static {p2, p1}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Lyp/g;

    .line 25
    .line 26
    invoke-static {p2}, Lcp/a;->b(Landroid/os/Parcel;)V

    .line 27
    .line 28
    .line 29
    check-cast p0, Llo/b0;

    .line 30
    .line 31
    new-instance p2, Lk0/g;

    .line 32
    .line 33
    const/16 v0, 0xb

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    invoke-direct {p2, p0, p1, v1, v0}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Llo/b0;->e:Landroid/os/Handler;

    .line 40
    .line 41
    invoke-virtual {p0, p2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :pswitch_3
    sget-object p0, Lcom/google/android/gms/common/api/Status;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 46
    .line 47
    invoke-static {p2, p0}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lcom/google/android/gms/common/api/Status;

    .line 52
    .line 53
    sget-object p0, Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 54
    .line 55
    invoke-static {p2, p0}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;

    .line 60
    .line 61
    invoke-static {p2}, Lcp/a;->b(Landroid/os/Parcel;)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :pswitch_4
    sget-object p0, Lcom/google/android/gms/common/api/Status;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 66
    .line 67
    invoke-static {p2, p0}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Lcom/google/android/gms/common/api/Status;

    .line 72
    .line 73
    invoke-static {p2}, Lcp/a;->b(Landroid/os/Parcel;)V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :pswitch_5
    sget-object p0, Lcom/google/android/gms/common/api/Status;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 78
    .line 79
    invoke-static {p2, p0}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    check-cast p0, Lcom/google/android/gms/common/api/Status;

    .line 84
    .line 85
    invoke-static {p2}, Lcp/a;->b(Landroid/os/Parcel;)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :pswitch_6
    sget-object p0, Ljo/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 90
    .line 91
    invoke-static {p2, p0}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    check-cast p0, Ljo/b;

    .line 96
    .line 97
    sget-object p0, Lyp/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 98
    .line 99
    invoke-static {p2, p0}, Lcp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    check-cast p0, Lyp/b;

    .line 104
    .line 105
    invoke-static {p2}, Lcp/a;->b(Landroid/os/Parcel;)V

    .line 106
    .line 107
    .line 108
    :goto_0
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 109
    .line 110
    .line 111
    const/4 p0, 0x1

    .line 112
    return p0

    .line 113
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

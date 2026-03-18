.class public final Lcq/u1;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcq/v0;


# instance fields
.field public d:Lis/b;

.field public final e:[Landroid/content/IntentFilter;


# direct methods
.method public constructor <init>([Landroid/content/IntentFilter;)V
    .locals 2

    .line 1
    const-string v0, "com.google.android.gms.wearable.internal.IWearableListener"

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {p0, v0, v1}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lcq/u1;->e:[Landroid/content/IntentFilter;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final R(ILandroid/os/Parcel;Landroid/os/Parcel;)Z
    .locals 0

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
    sget-object p0, Lcq/i1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lcq/i1;

    .line 13
    .line 14
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 15
    .line 16
    .line 17
    goto/16 :goto_1

    .line 18
    .line 19
    :pswitch_2
    sget-object p0, Lcq/b1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 20
    .line 21
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lcq/b1;

    .line 26
    .line 27
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lcq/b1;->e:Lcom/google/android/gms/common/data/DataHolder;

    .line 31
    .line 32
    invoke-virtual {p0}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 33
    .line 34
    .line 35
    goto/16 :goto_1

    .line 36
    .line 37
    :pswitch_3
    sget-object p0, Lcq/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 38
    .line 39
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Lcq/j;

    .line 44
    .line 45
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 46
    .line 47
    .line 48
    goto/16 :goto_1

    .line 49
    .line 50
    :pswitch_4
    sget-object p0, Lcq/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 51
    .line 52
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Lcq/k;

    .line 57
    .line 58
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 59
    .line 60
    .line 61
    goto/16 :goto_1

    .line 62
    .line 63
    :pswitch_5
    sget-object p0, Lcq/z0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 64
    .line 65
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    check-cast p0, Lcq/z0;

    .line 70
    .line 71
    invoke-virtual {p2}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-nez p0, :cond_0

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_0
    const-string p1, "com.google.android.gms.wearable.internal.IRpcResponseCallback"

    .line 79
    .line 80
    invoke-interface {p0, p1}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 81
    .line 82
    .line 83
    :goto_0
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 84
    .line 85
    .line 86
    goto/16 :goto_1

    .line 87
    .line 88
    :pswitch_6
    sget-object p0, Lcq/q1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 89
    .line 90
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    check-cast p0, Lcq/q1;

    .line 95
    .line 96
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 97
    .line 98
    .line 99
    goto/16 :goto_1

    .line 100
    .line 101
    :pswitch_7
    sget-object p0, Lcq/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 102
    .line 103
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    check-cast p0, Lcq/b;

    .line 108
    .line 109
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :pswitch_8
    sget-object p0, Lcq/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 114
    .line 115
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    check-cast p0, Lcq/d;

    .line 120
    .line 121
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 122
    .line 123
    .line 124
    goto :goto_1

    .line 125
    :pswitch_9
    sget-object p0, Lcq/x1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 126
    .line 127
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    check-cast p0, Lcq/x1;

    .line 132
    .line 133
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 134
    .line 135
    .line 136
    goto :goto_1

    .line 137
    :pswitch_a
    sget-object p0, Lcq/c1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 138
    .line 139
    invoke-virtual {p2, p0}, Landroid/os/Parcel;->createTypedArrayList(Landroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 140
    .line 141
    .line 142
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :pswitch_b
    sget-object p0, Lcq/c1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 147
    .line 148
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    check-cast p0, Lcq/c1;

    .line 153
    .line 154
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 155
    .line 156
    .line 157
    goto :goto_1

    .line 158
    :pswitch_c
    sget-object p0, Lcq/c1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 159
    .line 160
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    check-cast p0, Lcq/c1;

    .line 165
    .line 166
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 167
    .line 168
    .line 169
    goto :goto_1

    .line 170
    :pswitch_d
    sget-object p0, Lcq/z0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 171
    .line 172
    invoke-static {p2, p0}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    check-cast p0, Lcq/z0;

    .line 177
    .line 178
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 179
    .line 180
    .line 181
    goto :goto_1

    .line 182
    :pswitch_e
    sget-object p1, Lcom/google/android/gms/common/data/DataHolder;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 183
    .line 184
    invoke-static {p2, p1}, Lop/e;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    check-cast p1, Lcom/google/android/gms/common/data/DataHolder;

    .line 189
    .line 190
    invoke-static {p2}, Lop/e;->b(Landroid/os/Parcel;)V

    .line 191
    .line 192
    .line 193
    iget-object p0, p0, Lcq/u1;->d:Lis/b;

    .line 194
    .line 195
    if-eqz p0, :cond_1

    .line 196
    .line 197
    new-instance p2, La0/j;

    .line 198
    .line 199
    const/16 p3, 0xc

    .line 200
    .line 201
    invoke-direct {p2, p1, p3}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {p0, p2}, Lis/b;->a(Llo/l;)V

    .line 205
    .line 206
    .line 207
    goto :goto_1

    .line 208
    :cond_1
    invoke-virtual {p1}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 209
    .line 210
    .line 211
    :goto_1
    const/4 p0, 0x1

    .line 212
    return p0

    .line 213
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final T()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcq/u1;->d:Lis/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-object v1, v0, Lis/b;->b:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object v1, v0, Lis/b;->c:Ljava/lang/Object;

    .line 9
    .line 10
    :cond_0
    iput-object v1, p0, Lcq/u1;->d:Lis/b;

    .line 11
    .line 12
    return-void
.end method

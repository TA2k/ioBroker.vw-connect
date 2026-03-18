.class public final Lcom/google/android/gms/maps/GoogleMapOptions;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/common/internal/ReflectedParcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/gms/maps/GoogleMapOptions;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:Ljava/lang/Boolean;

.field public e:Ljava/lang/Boolean;

.field public f:I

.field public g:Lcom/google/android/gms/maps/model/CameraPosition;

.field public h:Ljava/lang/Boolean;

.field public i:Ljava/lang/Boolean;

.field public j:Ljava/lang/Boolean;

.field public k:Ljava/lang/Boolean;

.field public l:Ljava/lang/Boolean;

.field public m:Ljava/lang/Boolean;

.field public n:Ljava/lang/Boolean;

.field public o:Ljava/lang/Boolean;

.field public p:Ljava/lang/Boolean;

.field public q:Ljava/lang/Float;

.field public r:Ljava/lang/Float;

.field public s:Lcom/google/android/gms/maps/model/LatLngBounds;

.field public t:Ljava/lang/Boolean;

.field public u:Ljava/lang/Integer;

.field public v:Ljava/lang/String;

.field public w:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpp/h;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lpp/h;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/gms/maps/GoogleMapOptions;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    const/16 v0, 0xe9

    .line 10
    .line 11
    const/16 v1, 0xe1

    .line 12
    .line 13
    const/16 v2, 0xff

    .line 14
    .line 15
    const/16 v3, 0xec

    .line 16
    .line 17
    invoke-static {v2, v3, v0, v1}, Landroid/graphics/Color;->argb(IIII)I

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->f:I

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput-object v0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->q:Ljava/lang/Float;

    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->r:Ljava/lang/Float;

    .line 11
    .line 12
    iput-object v0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->s:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 13
    .line 14
    iput-object v0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->u:Ljava/lang/Integer;

    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->v:Ljava/lang/String;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Lb81/c;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lb81/c;-><init>(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->f:I

    .line 7
    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "MapType"

    .line 13
    .line 14
    invoke-virtual {v0, v1, v2}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v1, "LiteMode"

    .line 18
    .line 19
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->n:Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-string v1, "Camera"

    .line 25
    .line 26
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->g:Lcom/google/android/gms/maps/model/CameraPosition;

    .line 27
    .line 28
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v1, "CompassEnabled"

    .line 32
    .line 33
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->i:Ljava/lang/Boolean;

    .line 34
    .line 35
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v1, "ZoomControlsEnabled"

    .line 39
    .line 40
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->h:Ljava/lang/Boolean;

    .line 41
    .line 42
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const-string v1, "ScrollGesturesEnabled"

    .line 46
    .line 47
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->j:Ljava/lang/Boolean;

    .line 48
    .line 49
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const-string v1, "ZoomGesturesEnabled"

    .line 53
    .line 54
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->k:Ljava/lang/Boolean;

    .line 55
    .line 56
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v1, "TiltGesturesEnabled"

    .line 60
    .line 61
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->l:Ljava/lang/Boolean;

    .line 62
    .line 63
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    const-string v1, "RotateGesturesEnabled"

    .line 67
    .line 68
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->m:Ljava/lang/Boolean;

    .line 69
    .line 70
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const-string v1, "ScrollGesturesEnabledDuringRotateOrZoom"

    .line 74
    .line 75
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->t:Ljava/lang/Boolean;

    .line 76
    .line 77
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    const-string v1, "MapToolbarEnabled"

    .line 81
    .line 82
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->o:Ljava/lang/Boolean;

    .line 83
    .line 84
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const-string v1, "AmbientEnabled"

    .line 88
    .line 89
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->p:Ljava/lang/Boolean;

    .line 90
    .line 91
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    const-string v1, "MinZoomPreference"

    .line 95
    .line 96
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->q:Ljava/lang/Float;

    .line 97
    .line 98
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string v1, "MaxZoomPreference"

    .line 102
    .line 103
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->r:Ljava/lang/Float;

    .line 104
    .line 105
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const-string v1, "BackgroundColor"

    .line 109
    .line 110
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->u:Ljava/lang/Integer;

    .line 111
    .line 112
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const-string v1, "LatLngBoundsForCameraTarget"

    .line 116
    .line 117
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->s:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 118
    .line 119
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const-string v1, "ZOrderOnTop"

    .line 123
    .line 124
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->d:Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const-string v1, "UseViewLifecycleInFragment"

    .line 130
    .line 131
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->e:Ljava/lang/Boolean;

    .line 132
    .line 133
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    iget p0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->w:I

    .line 137
    .line 138
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    const-string v1, "mapColorScheme"

    .line 143
    .line 144
    invoke-virtual {v0, p0, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0}, Lb81/c;->toString()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->d:Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x2

    .line 14
    const/4 v3, 0x4

    .line 15
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 19
    .line 20
    .line 21
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->e:Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    const/4 v2, 0x3

    .line 28
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 32
    .line 33
    .line 34
    iget v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->f:I

    .line 35
    .line 36
    invoke-static {p1, v3, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 40
    .line 41
    .line 42
    const/4 v1, 0x5

    .line 43
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->g:Lcom/google/android/gms/maps/model/CameraPosition;

    .line 44
    .line 45
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->h:Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    const/4 v2, 0x6

    .line 55
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 59
    .line 60
    .line 61
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->i:Ljava/lang/Boolean;

    .line 62
    .line 63
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    const/4 v2, 0x7

    .line 68
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 72
    .line 73
    .line 74
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->j:Ljava/lang/Boolean;

    .line 75
    .line 76
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    const/16 v2, 0x8

    .line 81
    .line 82
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->k:Ljava/lang/Boolean;

    .line 89
    .line 90
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    const/16 v2, 0x9

    .line 95
    .line 96
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 100
    .line 101
    .line 102
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->l:Ljava/lang/Boolean;

    .line 103
    .line 104
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    const/16 v2, 0xa

    .line 109
    .line 110
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 114
    .line 115
    .line 116
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->m:Ljava/lang/Boolean;

    .line 117
    .line 118
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    const/16 v2, 0xb

    .line 123
    .line 124
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 128
    .line 129
    .line 130
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->n:Ljava/lang/Boolean;

    .line 131
    .line 132
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    const/16 v2, 0xc

    .line 137
    .line 138
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 142
    .line 143
    .line 144
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->o:Ljava/lang/Boolean;

    .line 145
    .line 146
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    const/16 v2, 0xe

    .line 151
    .line 152
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 156
    .line 157
    .line 158
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->p:Ljava/lang/Boolean;

    .line 159
    .line 160
    invoke-static {v1}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    const/16 v2, 0xf

    .line 165
    .line 166
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 170
    .line 171
    .line 172
    const/16 v1, 0x10

    .line 173
    .line 174
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->q:Ljava/lang/Float;

    .line 175
    .line 176
    invoke-static {p1, v1, v2}, Ljp/dc;->h(Landroid/os/Parcel;ILjava/lang/Float;)V

    .line 177
    .line 178
    .line 179
    const/16 v1, 0x11

    .line 180
    .line 181
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->r:Ljava/lang/Float;

    .line 182
    .line 183
    invoke-static {p1, v1, v2}, Ljp/dc;->h(Landroid/os/Parcel;ILjava/lang/Float;)V

    .line 184
    .line 185
    .line 186
    const/16 v1, 0x12

    .line 187
    .line 188
    iget-object v2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->s:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 189
    .line 190
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 191
    .line 192
    .line 193
    iget-object p2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->t:Ljava/lang/Boolean;

    .line 194
    .line 195
    invoke-static {p2}, Lkp/y5;->f(Ljava/lang/Boolean;)B

    .line 196
    .line 197
    .line 198
    move-result p2

    .line 199
    const/16 v1, 0x13

    .line 200
    .line 201
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 205
    .line 206
    .line 207
    iget-object p2, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->u:Ljava/lang/Integer;

    .line 208
    .line 209
    if-nez p2, :cond_0

    .line 210
    .line 211
    goto :goto_0

    .line 212
    :cond_0
    const/16 v1, 0x14

    .line 213
    .line 214
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 218
    .line 219
    .line 220
    move-result p2

    .line 221
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 222
    .line 223
    .line 224
    :goto_0
    const/16 p2, 0x15

    .line 225
    .line 226
    iget-object v1, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->v:Ljava/lang/String;

    .line 227
    .line 228
    invoke-static {p1, v1, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 229
    .line 230
    .line 231
    iget p0, p0, Lcom/google/android/gms/maps/GoogleMapOptions;->w:I

    .line 232
    .line 233
    const/16 p2, 0x17

    .line 234
    .line 235
    invoke-static {p1, p2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 239
    .line 240
    .line 241
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 242
    .line 243
    .line 244
    return-void
.end method

.class public Lsp/l;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lsp/l;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:Lcom/google/android/gms/maps/model/LatLng;

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public g:Lsp/b;

.field public h:F

.field public i:F

.field public j:Z

.field public k:Z

.field public l:Z

.field public m:F

.field public n:F

.field public o:F

.field public p:F

.field public q:F

.field public r:I

.field public s:Landroid/view/View;

.field public t:I

.field public u:Ljava/lang/String;

.field public v:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lpp/h;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpp/h;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lsp/l;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f000000    # 0.5f

    .line 5
    .line 6
    iput v0, p0, Lsp/l;->h:F

    .line 7
    .line 8
    const/high16 v1, 0x3f800000    # 1.0f

    .line 9
    .line 10
    iput v1, p0, Lsp/l;->i:F

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    iput-boolean v2, p0, Lsp/l;->k:Z

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    iput-boolean v2, p0, Lsp/l;->l:Z

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    iput v3, p0, Lsp/l;->m:F

    .line 20
    .line 21
    iput v0, p0, Lsp/l;->n:F

    .line 22
    .line 23
    iput v3, p0, Lsp/l;->o:F

    .line 24
    .line 25
    iput v1, p0, Lsp/l;->p:F

    .line 26
    .line 27
    iput v2, p0, Lsp/l;->r:I

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

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
    const/4 v1, 0x2

    .line 8
    iget-object v2, p0, Lsp/l;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x3

    .line 14
    iget-object v1, p0, Lsp/l;->e:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {p1, v1, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    iget-object p2, p0, Lsp/l;->f:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    invoke-static {p1, p2, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    iget-object p2, p0, Lsp/l;->g:Lsp/b;

    .line 26
    .line 27
    if-nez p2, :cond_0

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object p2, p2, Lsp/b;->a:Lyo/a;

    .line 32
    .line 33
    invoke-interface {p2}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    :goto_0
    const/4 v2, 0x5

    .line 38
    invoke-static {p1, v2, p2}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 39
    .line 40
    .line 41
    iget p2, p0, Lsp/l;->h:F

    .line 42
    .line 43
    const/4 v2, 0x6

    .line 44
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 48
    .line 49
    .line 50
    iget p2, p0, Lsp/l;->i:F

    .line 51
    .line 52
    const/4 v2, 0x7

    .line 53
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 57
    .line 58
    .line 59
    iget-boolean p2, p0, Lsp/l;->j:Z

    .line 60
    .line 61
    const/16 v2, 0x8

    .line 62
    .line 63
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 67
    .line 68
    .line 69
    iget-boolean p2, p0, Lsp/l;->k:Z

    .line 70
    .line 71
    const/16 v2, 0x9

    .line 72
    .line 73
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 77
    .line 78
    .line 79
    iget-boolean p2, p0, Lsp/l;->l:Z

    .line 80
    .line 81
    const/16 v2, 0xa

    .line 82
    .line 83
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 87
    .line 88
    .line 89
    iget p2, p0, Lsp/l;->m:F

    .line 90
    .line 91
    const/16 v2, 0xb

    .line 92
    .line 93
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 97
    .line 98
    .line 99
    iget p2, p0, Lsp/l;->n:F

    .line 100
    .line 101
    const/16 v2, 0xc

    .line 102
    .line 103
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 107
    .line 108
    .line 109
    iget p2, p0, Lsp/l;->o:F

    .line 110
    .line 111
    const/16 v2, 0xd

    .line 112
    .line 113
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 117
    .line 118
    .line 119
    iget p2, p0, Lsp/l;->p:F

    .line 120
    .line 121
    const/16 v2, 0xe

    .line 122
    .line 123
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 127
    .line 128
    .line 129
    iget p2, p0, Lsp/l;->q:F

    .line 130
    .line 131
    const/16 v2, 0xf

    .line 132
    .line 133
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 137
    .line 138
    .line 139
    iget p2, p0, Lsp/l;->r:I

    .line 140
    .line 141
    const/16 v2, 0x11

    .line 142
    .line 143
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 147
    .line 148
    .line 149
    iget-object p2, p0, Lsp/l;->s:Landroid/view/View;

    .line 150
    .line 151
    new-instance v2, Lyo/b;

    .line 152
    .line 153
    invoke-direct {v2, p2}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    const/16 p2, 0x12

    .line 157
    .line 158
    invoke-static {p1, p2, v2}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 159
    .line 160
    .line 161
    iget p2, p0, Lsp/l;->t:I

    .line 162
    .line 163
    const/16 v2, 0x13

    .line 164
    .line 165
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 169
    .line 170
    .line 171
    const/16 p2, 0x14

    .line 172
    .line 173
    iget-object v2, p0, Lsp/l;->u:Ljava/lang/String;

    .line 174
    .line 175
    invoke-static {p1, v2, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 176
    .line 177
    .line 178
    iget p0, p0, Lsp/l;->v:F

    .line 179
    .line 180
    const/16 p2, 0x15

    .line 181
    .line 182
    invoke-static {p1, p2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeFloat(F)V

    .line 186
    .line 187
    .line 188
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 189
    .line 190
    .line 191
    return-void
.end method

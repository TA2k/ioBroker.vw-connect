.class public final Ljp/ve;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ljp/ve;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:I

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public g:I

.field public h:[Landroid/graphics/Point;

.field public i:Ljp/c8;

.field public j:Ljp/cb;

.field public k:Ljp/yb;

.field public l:Ljp/vd;

.field public m:Ljp/uc;

.field public n:Ljp/d9;

.field public o:Ljp/z4;

.field public p:Ljp/a6;

.field public q:Ljp/b7;

.field public r:[B

.field public s:Z

.field public t:D


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljp/a;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljp/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ljp/ve;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 5

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
    iget v1, p0, Ljp/ve;->d:I

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    const/4 v3, 0x4

    .line 11
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x3

    .line 18
    iget-object v2, p0, Ljp/ve;->e:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {p1, v2, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ljp/ve;->f:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p1, v1, v3}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    iget v1, p0, Ljp/ve;->g:I

    .line 29
    .line 30
    const/4 v2, 0x5

    .line 31
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 35
    .line 36
    .line 37
    const/4 v1, 0x6

    .line 38
    iget-object v2, p0, Ljp/ve;->h:[Landroid/graphics/Point;

    .line 39
    .line 40
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 41
    .line 42
    .line 43
    const/4 v1, 0x7

    .line 44
    iget-object v2, p0, Ljp/ve;->i:Ljp/c8;

    .line 45
    .line 46
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Ljp/ve;->j:Ljp/cb;

    .line 50
    .line 51
    const/16 v2, 0x8

    .line 52
    .line 53
    invoke-static {p1, v2, v1, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 54
    .line 55
    .line 56
    const/16 v1, 0x9

    .line 57
    .line 58
    iget-object v4, p0, Ljp/ve;->k:Ljp/yb;

    .line 59
    .line 60
    invoke-static {p1, v1, v4, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 61
    .line 62
    .line 63
    const/16 v1, 0xa

    .line 64
    .line 65
    iget-object v4, p0, Ljp/ve;->l:Ljp/vd;

    .line 66
    .line 67
    invoke-static {p1, v1, v4, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 68
    .line 69
    .line 70
    const/16 v1, 0xb

    .line 71
    .line 72
    iget-object v4, p0, Ljp/ve;->m:Ljp/uc;

    .line 73
    .line 74
    invoke-static {p1, v1, v4, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 75
    .line 76
    .line 77
    const/16 v1, 0xc

    .line 78
    .line 79
    iget-object v4, p0, Ljp/ve;->n:Ljp/d9;

    .line 80
    .line 81
    invoke-static {p1, v1, v4, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 82
    .line 83
    .line 84
    const/16 v1, 0xd

    .line 85
    .line 86
    iget-object v4, p0, Ljp/ve;->o:Ljp/z4;

    .line 87
    .line 88
    invoke-static {p1, v1, v4, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 89
    .line 90
    .line 91
    const/16 v1, 0xe

    .line 92
    .line 93
    iget-object v4, p0, Ljp/ve;->p:Ljp/a6;

    .line 94
    .line 95
    invoke-static {p1, v1, v4, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 96
    .line 97
    .line 98
    const/16 v1, 0xf

    .line 99
    .line 100
    iget-object v4, p0, Ljp/ve;->q:Ljp/b7;

    .line 101
    .line 102
    invoke-static {p1, v1, v4, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 103
    .line 104
    .line 105
    const/16 p2, 0x10

    .line 106
    .line 107
    iget-object v1, p0, Ljp/ve;->r:[B

    .line 108
    .line 109
    invoke-static {p1, p2, v1}, Ljp/dc;->g(Landroid/os/Parcel;I[B)V

    .line 110
    .line 111
    .line 112
    iget-boolean p2, p0, Ljp/ve;->s:Z

    .line 113
    .line 114
    const/16 v1, 0x11

    .line 115
    .line 116
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 120
    .line 121
    .line 122
    iget-wide v3, p0, Ljp/ve;->t:D

    .line 123
    .line 124
    const/16 p0, 0x12

    .line 125
    .line 126
    invoke-static {p1, p0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeDouble(D)V

    .line 130
    .line 131
    .line 132
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 133
    .line 134
    .line 135
    return-void
.end method

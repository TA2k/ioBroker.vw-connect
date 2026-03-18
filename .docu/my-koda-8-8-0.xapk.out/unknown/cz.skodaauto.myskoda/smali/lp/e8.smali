.class public final Llp/e8;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Llp/e8;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:[Llp/yd;

.field public final e:Llp/y1;

.field public final f:Llp/y1;

.field public final g:Llp/y1;

.field public final h:Ljava/lang/String;

.field public final i:F

.field public final j:Ljava/lang/String;

.field public final k:I

.field public final l:Z

.field public final m:I

.field public final n:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Llp/z2;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Llp/z2;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Llp/e8;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>([Llp/yd;Llp/y1;Llp/y1;Llp/y1;Ljava/lang/String;FLjava/lang/String;IZII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llp/e8;->d:[Llp/yd;

    .line 5
    .line 6
    iput-object p2, p0, Llp/e8;->e:Llp/y1;

    .line 7
    .line 8
    iput-object p3, p0, Llp/e8;->f:Llp/y1;

    .line 9
    .line 10
    iput-object p4, p0, Llp/e8;->g:Llp/y1;

    .line 11
    .line 12
    iput-object p5, p0, Llp/e8;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput p6, p0, Llp/e8;->i:F

    .line 15
    .line 16
    iput-object p7, p0, Llp/e8;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput p8, p0, Llp/e8;->k:I

    .line 19
    .line 20
    iput-boolean p9, p0, Llp/e8;->l:Z

    .line 21
    .line 22
    iput p10, p0, Llp/e8;->m:I

    .line 23
    .line 24
    iput p11, p0, Llp/e8;->n:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
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
    const/4 v1, 0x2

    .line 8
    iget-object v2, p0, Llp/e8;->d:[Llp/yd;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    iget-object v2, p0, Llp/e8;->e:Llp/y1;

    .line 15
    .line 16
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 17
    .line 18
    .line 19
    iget-object v1, p0, Llp/e8;->f:Llp/y1;

    .line 20
    .line 21
    const/4 v2, 0x4

    .line 22
    invoke-static {p1, v2, v1, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 23
    .line 24
    .line 25
    const/4 v1, 0x5

    .line 26
    iget-object v3, p0, Llp/e8;->g:Llp/y1;

    .line 27
    .line 28
    invoke-static {p1, v1, v3, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 29
    .line 30
    .line 31
    const/4 p2, 0x6

    .line 32
    iget-object v1, p0, Llp/e8;->h:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {p1, v1, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    const/4 p2, 0x7

    .line 38
    invoke-static {p1, p2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 39
    .line 40
    .line 41
    iget p2, p0, Llp/e8;->i:F

    .line 42
    .line 43
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeFloat(F)V

    .line 44
    .line 45
    .line 46
    const/16 p2, 0x8

    .line 47
    .line 48
    iget-object v1, p0, Llp/e8;->j:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {p1, v1, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 51
    .line 52
    .line 53
    const/16 p2, 0x9

    .line 54
    .line 55
    invoke-static {p1, p2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 56
    .line 57
    .line 58
    iget p2, p0, Llp/e8;->k:I

    .line 59
    .line 60
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 61
    .line 62
    .line 63
    const/16 p2, 0xa

    .line 64
    .line 65
    invoke-static {p1, p2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 66
    .line 67
    .line 68
    iget-boolean p2, p0, Llp/e8;->l:Z

    .line 69
    .line 70
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 71
    .line 72
    .line 73
    const/16 p2, 0xb

    .line 74
    .line 75
    invoke-static {p1, p2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 76
    .line 77
    .line 78
    iget p2, p0, Llp/e8;->m:I

    .line 79
    .line 80
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 81
    .line 82
    .line 83
    const/16 p2, 0xc

    .line 84
    .line 85
    invoke-static {p1, p2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 86
    .line 87
    .line 88
    iget p0, p0, Llp/e8;->n:I

    .line 89
    .line 90
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 91
    .line 92
    .line 93
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 94
    .line 95
    .line 96
    return-void
.end method

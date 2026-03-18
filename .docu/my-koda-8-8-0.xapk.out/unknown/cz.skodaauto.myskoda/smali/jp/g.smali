.class public final Ljp/g;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ljp/g;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:I

.field public final e:I

.field public final f:I

.field public final g:J

.field public final h:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljp/a;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljp/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ljp/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(JIIII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Ljp/g;->d:I

    .line 5
    .line 6
    iput p4, p0, Ljp/g;->e:I

    .line 7
    .line 8
    iput p5, p0, Ljp/g;->f:I

    .line 9
    .line 10
    iput-wide p1, p0, Ljp/g;->g:J

    .line 11
    .line 12
    iput p6, p0, Ljp/g;->h:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const/16 p2, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    iget v0, p0, Ljp/g;->d:I

    .line 8
    .line 9
    const/4 v1, 0x2

    .line 10
    const/4 v2, 0x4

    .line 11
    invoke-static {p1, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x3

    .line 18
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 19
    .line 20
    .line 21
    iget v0, p0, Ljp/g;->e:I

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 24
    .line 25
    .line 26
    invoke-static {p1, v2, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 27
    .line 28
    .line 29
    iget v0, p0, Ljp/g;->f:I

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 32
    .line 33
    .line 34
    const/16 v0, 0x8

    .line 35
    .line 36
    const/4 v1, 0x5

    .line 37
    invoke-static {p1, v1, v0}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 38
    .line 39
    .line 40
    iget-wide v0, p0, Ljp/g;->g:J

    .line 41
    .line 42
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 43
    .line 44
    .line 45
    const/4 v0, 0x6

    .line 46
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 47
    .line 48
    .line 49
    iget p0, p0, Ljp/g;->h:I

    .line 50
    .line 51
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 52
    .line 53
    .line 54
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

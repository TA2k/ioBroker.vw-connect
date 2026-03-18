.class public final Lno/g;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lno/g;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lno/o;

.field public final e:Z

.field public final f:Z

.field public final g:[I

.field public final h:I

.field public final i:[I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lkg/l0;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lkg/l0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lno/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lno/o;ZZ[II[I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lno/g;->d:Lno/o;

    .line 5
    .line 6
    iput-boolean p2, p0, Lno/g;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lno/g;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lno/g;->g:[I

    .line 11
    .line 12
    iput p5, p0, Lno/g;->h:I

    .line 13
    .line 14
    iput-object p6, p0, Lno/g;->i:[I

    .line 15
    .line 16
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
    const/4 v1, 0x1

    .line 8
    iget-object v2, p0, Lno/g;->d:Lno/o;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x2

    .line 14
    const/4 v1, 0x4

    .line 15
    invoke-static {p1, p2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 16
    .line 17
    .line 18
    iget-boolean p2, p0, Lno/g;->e:Z

    .line 19
    .line 20
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 21
    .line 22
    .line 23
    const/4 p2, 0x3

    .line 24
    invoke-static {p1, p2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 25
    .line 26
    .line 27
    iget-boolean p2, p0, Lno/g;->f:Z

    .line 28
    .line 29
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 30
    .line 31
    .line 32
    iget-object p2, p0, Lno/g;->g:[I

    .line 33
    .line 34
    invoke-static {p1, v1, p2}, Ljp/dc;->j(Landroid/os/Parcel;I[I)V

    .line 35
    .line 36
    .line 37
    const/4 p2, 0x5

    .line 38
    invoke-static {p1, p2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 39
    .line 40
    .line 41
    iget p2, p0, Lno/g;->h:I

    .line 42
    .line 43
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 44
    .line 45
    .line 46
    const/4 p2, 0x6

    .line 47
    iget-object p0, p0, Lno/g;->i:[I

    .line 48
    .line 49
    invoke-static {p1, p2, p0}, Ljp/dc;->j(Landroid/os/Parcel;I[I)V

    .line 50
    .line 51
    .line 52
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.class public final Lfs/f;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lfs/f;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:[Lcom/google/firebase/appindexing/internal/Thing;

.field public final f:[Ljava/lang/String;

.field public final g:[Ljava/lang/String;

.field public final h:Lbp/p;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfs/b;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lfs/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lfs/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(I[Lcom/google/firebase/appindexing/internal/Thing;[Ljava/lang/String;[Ljava/lang/String;Lbp/p;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    if-eq p1, v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x2

    .line 10
    if-eq p1, v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x3

    .line 13
    if-eq p1, v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    if-eq p1, v0, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x6

    .line 19
    if-eq p1, v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x7

    .line 22
    if-eq p1, v0, :cond_0

    .line 23
    .line 24
    const/4 p1, 0x0

    .line 25
    :cond_0
    iput p1, p0, Lfs/f;->d:I

    .line 26
    .line 27
    iput-object p2, p0, Lfs/f;->e:[Lcom/google/firebase/appindexing/internal/Thing;

    .line 28
    .line 29
    iput-object p3, p0, Lfs/f;->f:[Ljava/lang/String;

    .line 30
    .line 31
    iput-object p4, p0, Lfs/f;->g:[Ljava/lang/String;

    .line 32
    .line 33
    iput-object p5, p0, Lfs/f;->h:Lbp/p;

    .line 34
    .line 35
    iput-object p6, p0, Lfs/f;->i:Ljava/lang/String;

    .line 36
    .line 37
    iput-object p7, p0, Lfs/f;->j:Ljava/lang/String;

    .line 38
    .line 39
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
    const/4 v1, 0x4

    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 10
    .line 11
    .line 12
    iget v1, p0, Lfs/f;->d:I

    .line 13
    .line 14
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    iget-object v2, p0, Lfs/f;->e:[Lcom/google/firebase/appindexing/internal/Thing;

    .line 19
    .line 20
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 21
    .line 22
    .line 23
    const/4 v1, 0x3

    .line 24
    iget-object v2, p0, Lfs/f;->f:[Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {p1, v1, v2}, Ljp/dc;->o(Landroid/os/Parcel;I[Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const/4 v1, 0x5

    .line 30
    iget-object v2, p0, Lfs/f;->g:[Ljava/lang/String;

    .line 31
    .line 32
    invoke-static {p1, v1, v2}, Ljp/dc;->o(Landroid/os/Parcel;I[Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const/4 v1, 0x6

    .line 36
    iget-object v2, p0, Lfs/f;->h:Lbp/p;

    .line 37
    .line 38
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 39
    .line 40
    .line 41
    const/4 p2, 0x7

    .line 42
    iget-object v1, p0, Lfs/f;->i:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {p1, v1, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 45
    .line 46
    .line 47
    const/16 p2, 0x8

    .line 48
    .line 49
    iget-object p0, p0, Lfs/f;->j:Ljava/lang/String;

    .line 50
    .line 51
    invoke-static {p1, p0, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 52
    .line 53
    .line 54
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

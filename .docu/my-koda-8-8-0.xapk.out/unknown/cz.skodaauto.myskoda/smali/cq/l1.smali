.class public final Lcq/l1;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcq/l1;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:J

.field public final f:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcq/x0;

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcq/x0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcq/l1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(IJLjava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcq/l1;->d:I

    .line 5
    .line 6
    iput-wide p2, p0, Lcq/l1;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lcq/l1;->f:Ljava/util/List;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

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
    const/4 v0, 0x2

    .line 8
    const/4 v1, 0x4

    .line 9
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 10
    .line 11
    .line 12
    iget v0, p0, Lcq/l1;->d:I

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/16 v0, 0x8

    .line 18
    .line 19
    const/4 v2, 0x3

    .line 20
    invoke-static {p1, v2, v0}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 21
    .line 22
    .line 23
    iget-wide v2, p0, Lcq/l1;->e:J

    .line 24
    .line 25
    invoke-virtual {p1, v2, v3}, Landroid/os/Parcel;->writeLong(J)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lcq/l1;->f:Ljava/util/List;

    .line 29
    .line 30
    invoke-static {p1, v1, p0}, Ljp/dc;->r(Landroid/os/Parcel;ILjava/util/List;)V

    .line 31
    .line 32
    .line 33
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.class public final Ljp/d9;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ljp/d9;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:D

.field public e:D


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljp/a;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Ljp/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ljp/d9;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
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
    iget-wide v0, p0, Ljp/d9;->d:D

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    const/16 v3, 0x8

    .line 11
    .line 12
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 16
    .line 17
    .line 18
    iget-wide v0, p0, Ljp/d9;->e:D

    .line 19
    .line 20
    const/4 p0, 0x3

    .line 21
    invoke-static {p1, p0, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

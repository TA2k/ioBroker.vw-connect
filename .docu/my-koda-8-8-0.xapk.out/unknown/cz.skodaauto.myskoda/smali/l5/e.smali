.class public final Ll5/e;
.super Lj6/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ll5/e;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public f:Landroid/util/SparseArray;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lv2/n;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lv2/n;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ll5/e;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V
    .locals 5

    .line 1
    invoke-direct {p0, p1, p2}, Lj6/b;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    new-array v1, v0, [I

    .line 9
    .line 10
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->readIntArray([I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->readParcelableArray(Ljava/lang/ClassLoader;)[Landroid/os/Parcelable;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    new-instance p2, Landroid/util/SparseArray;

    .line 18
    .line 19
    invoke-direct {p2, v0}, Landroid/util/SparseArray;-><init>(I)V

    .line 20
    .line 21
    .line 22
    iput-object p2, p0, Ll5/e;->f:Landroid/util/SparseArray;

    .line 23
    .line 24
    const/4 p2, 0x0

    .line 25
    :goto_0
    if-ge p2, v0, :cond_0

    .line 26
    .line 27
    iget-object v2, p0, Ll5/e;->f:Landroid/util/SparseArray;

    .line 28
    .line 29
    aget v3, v1, p2

    .line 30
    .line 31
    aget-object v4, p1, p2

    .line 32
    .line 33
    invoke-virtual {v2, v3, v4}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    add-int/lit8 p2, p2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 5

    .line 1
    invoke-super {p0, p1, p2}, Lj6/b;->writeToParcel(Landroid/os/Parcel;I)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ll5/e;->f:Landroid/util/SparseArray;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v0, v1

    .line 15
    :goto_0
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 16
    .line 17
    .line 18
    new-array v2, v0, [I

    .line 19
    .line 20
    new-array v3, v0, [Landroid/os/Parcelable;

    .line 21
    .line 22
    :goto_1
    if-ge v1, v0, :cond_1

    .line 23
    .line 24
    iget-object v4, p0, Ll5/e;->f:Landroid/util/SparseArray;

    .line 25
    .line 26
    invoke-virtual {v4, v1}, Landroid/util/SparseArray;->keyAt(I)I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    aput v4, v2, v1

    .line 31
    .line 32
    iget-object v4, p0, Ll5/e;->f:Landroid/util/SparseArray;

    .line 33
    .line 34
    invoke-virtual {v4, v1}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    check-cast v4, Landroid/os/Parcelable;

    .line 39
    .line 40
    aput-object v4, v3, v1

    .line 41
    .line 42
    add-int/lit8 v1, v1, 0x1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeIntArray([I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, v3, p2}, Landroid/os/Parcel;->writeParcelableArray([Landroid/os/Parcelable;I)V

    .line 49
    .line 50
    .line 51
    return-void
.end method

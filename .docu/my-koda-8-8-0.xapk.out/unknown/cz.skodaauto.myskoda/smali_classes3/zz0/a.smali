.class public final Lzz0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lzz0/a;",
            ">;"
        }
    .end annotation
.end field

.field public static final e:[C


# instance fields
.field public d:[B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "0123456789ABCDEF"

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lzz0/a;->e:[C

    .line 8
    .line 9
    new-instance v0, Lzg/g2;

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    invoke-direct {v0, v1}, Lzg/g2;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lzz0/a;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>([B)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzz0/a;->d:[B

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final h()Ljava/lang/Integer;
    .locals 3

    .line 1
    iget-object p0, p0, Lzz0/a;->d:[B

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    array-length v1, p0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v1, v0

    .line 9
    :goto_0
    const/4 v2, 0x1

    .line 10
    if-le v2, v1, :cond_1

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return-object p0

    .line 14
    :cond_1
    aget-byte p0, p0, v0

    .line 15
    .line 16
    and-int/lit16 p0, p0, 0xff

    .line 17
    .line 18
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object p0, p0, Lzz0/a;->d:[B

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    array-length v1, p0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v1, v0

    .line 9
    :goto_0
    if-nez v1, :cond_1

    .line 10
    .line 11
    const-string p0, ""

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_1
    array-length v1, p0

    .line 15
    mul-int/lit8 v1, v1, 0x3

    .line 16
    .line 17
    add-int/lit8 v1, v1, -0x1

    .line 18
    .line 19
    new-array v1, v1, [C

    .line 20
    .line 21
    :goto_1
    array-length v2, p0

    .line 22
    if-ge v0, v2, :cond_3

    .line 23
    .line 24
    aget-byte v2, p0, v0

    .line 25
    .line 26
    and-int/lit16 v3, v2, 0xff

    .line 27
    .line 28
    mul-int/lit8 v4, v0, 0x3

    .line 29
    .line 30
    ushr-int/lit8 v3, v3, 0x4

    .line 31
    .line 32
    sget-object v5, Lzz0/a;->e:[C

    .line 33
    .line 34
    aget-char v3, v5, v3

    .line 35
    .line 36
    aput-char v3, v1, v4

    .line 37
    .line 38
    add-int/lit8 v3, v4, 0x1

    .line 39
    .line 40
    and-int/lit8 v2, v2, 0xf

    .line 41
    .line 42
    aget-char v2, v5, v2

    .line 43
    .line 44
    aput-char v2, v1, v3

    .line 45
    .line 46
    array-length v2, p0

    .line 47
    add-int/lit8 v2, v2, -0x1

    .line 48
    .line 49
    if-eq v0, v2, :cond_2

    .line 50
    .line 51
    add-int/lit8 v4, v4, 0x2

    .line 52
    .line 53
    const/16 v2, 0x2d

    .line 54
    .line 55
    aput-char v2, v1, v4

    .line 56
    .line 57
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    new-instance p0, Ljava/lang/String;

    .line 61
    .line 62
    invoke-direct {p0, v1}, Ljava/lang/String;-><init>([C)V

    .line 63
    .line 64
    .line 65
    const-string v0, "(0x) "

    .line 66
    .line 67
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lzz0/a;->d:[B

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeByteArray([B)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.class public Lorg/altbeacon/beacon/Region;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;
.implements Ljava/io/Serializable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation
.end field

.field private static final MAC_PATTERN:Ljava/util/regex/Pattern;

.field private static final TAG:Ljava/lang/String; = "Region"


# instance fields
.field protected final mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

.field protected final mBluetoothAddress:Ljava/lang/String;

.field protected final mIdentifiers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;"
        }
    .end annotation
.end field

.field protected final mUniqueId:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "^[0-9A-Fa-f]{2}\\:[0-9A-Fa-f]{2}\\:[0-9A-Fa-f]{2}\\:[0-9A-Fa-f]{2}\\:[0-9A-Fa-f]{2}\\:[0-9A-Fa-f]{2}$"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lorg/altbeacon/beacon/Region;->MAC_PATTERN:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    new-instance v0, Lorg/altbeacon/beacon/Region$1;

    .line 10
    .line 11
    invoke-direct {v0}, Lorg/altbeacon/beacon/Region$1;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lorg/altbeacon/beacon/Region;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 4

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 39
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    .line 40
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    .line 41
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v1, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    const/4 v1, 0x0

    :goto_0
    const/4 v2, 0x0

    if-ge v1, v0, :cond_1

    .line 42
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v3

    if-nez v3, :cond_0

    .line 43
    iget-object v3, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_1

    .line 44
    :cond_0
    invoke-static {v3}, Lorg/altbeacon/beacon/Identifier;->parse(Ljava/lang/String;)Lorg/altbeacon/beacon/Identifier;

    move-result-object v2

    .line 45
    iget-object v3, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 46
    :cond_1
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    .line 47
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconParser;->fromString(Ljava/lang/String;)Lorg/altbeacon/beacon/BeaconParser;

    move-result-object p1

    iput-object p1, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    return-void

    .line 48
    :cond_2
    iput-object v2, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    invoke-direct {p0, p2}, Lorg/altbeacon/beacon/Region;->validateMac(Ljava/lang/String;)V

    .line 32
    iput-object p2, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    .line 33
    iput-object p1, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 34
    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    const/4 p2, 0x0

    .line 35
    iput-object p2, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    if-eqz p1, :cond_0

    return-void

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "uniqueId may not be null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;)V"
        }
    .end annotation

    const/4 v0, 0x0

    .line 10
    invoke-direct {p0, p1, p2, v0}, Lorg/altbeacon/beacon/Region;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    invoke-direct {p0, p3}, Lorg/altbeacon/beacon/Region;->validateMac(Ljava/lang/String;)V

    .line 13
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 14
    iput-object p1, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 15
    iput-object p3, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    const/4 p2, 0x0

    .line 16
    iput-object p2, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    if-eqz p1, :cond_0

    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "uniqueId may not be null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Ljava/lang/String;Lorg/altbeacon/beacon/BeaconParser;Ljava/util/List;Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lorg/altbeacon/beacon/BeaconParser;",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;",
            "Ljava/lang/String;",
            "I)V"
        }
    .end annotation

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    invoke-direct {p0, p4}, Lorg/altbeacon/beacon/Region;->validateMac(Ljava/lang/String;)V

    if-nez p3, :cond_0

    .line 20
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    iput-object p3, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    goto :goto_0

    .line 21
    :cond_0
    new-instance p5, Ljava/util/ArrayList;

    invoke-direct {p5, p3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object p5, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 22
    :goto_0
    iput-object p1, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 23
    iput-object p4, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    .line 24
    iput-object p2, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    if-eqz p1, :cond_1

    return-void

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "uniqueId may not be null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Ljava/lang/String;Lorg/altbeacon/beacon/BeaconParser;Lorg/altbeacon/beacon/Identifier;Lorg/altbeacon/beacon/Identifier;Lorg/altbeacon/beacon/Identifier;)V
    .locals 6

    .line 26
    new-instance v3, Ljava/util/ArrayList;

    const/4 v0, 0x3

    invoke-direct {v3, v0}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v4, 0x0

    const/4 v5, 0x3

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    invoke-direct/range {v0 .. v5}, Lorg/altbeacon/beacon/Region;-><init>(Ljava/lang/String;Lorg/altbeacon/beacon/BeaconParser;Ljava/util/List;Ljava/lang/String;I)V

    .line 27
    iget-object p0, v0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    invoke-interface {p0, p3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 28
    iget-object p0, v0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    invoke-interface {p0, p4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 29
    iget-object p0, v0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    invoke-interface {p0, p5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lorg/altbeacon/beacon/Identifier;Lorg/altbeacon/beacon/Identifier;Lorg/altbeacon/beacon/Identifier;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/util/ArrayList;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 3
    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 4
    invoke-interface {v0, p3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 5
    invoke-interface {v0, p4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 6
    iput-object p1, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    const/4 p2, 0x0

    .line 7
    iput-object p2, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    .line 8
    iput-object p2, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    if-eqz p1, :cond_0

    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "uniqueId may not be null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private validateMac(Ljava/lang/String;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    sget-object p0, Lorg/altbeacon/beacon/Region;->MAC_PATTERN:Ljava/util/regex/Pattern;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string v0, "Invalid mac address: \'"

    .line 19
    .line 20
    const-string v1, "\' Must be 6 hex bytes separated by colons."

    .line 21
    .line 22
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    :goto_0
    return-void
.end method


# virtual methods
.method public bridge synthetic clone()Ljava/lang/Object;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Region;->clone()Lorg/altbeacon/beacon/Region;

    move-result-object p0

    return-object p0
.end method

.method public clone()Lorg/altbeacon/beacon/Region;
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 2
    new-instance v0, Lorg/altbeacon/beacon/Region;

    iget-object v1, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    iget-object v2, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    invoke-direct {v0, v1, v2, p0}, Lorg/altbeacon/beacon/Region;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    return-object v0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lorg/altbeacon/beacon/Region;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lorg/altbeacon/beacon/Region;

    .line 6
    .line 7
    iget-object p1, p1, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 8
    .line 9
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public getBluetoothAddress()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getId1()Lorg/altbeacon/beacon/Identifier;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public getId2()Lorg/altbeacon/beacon/Identifier;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public getId3()Lorg/altbeacon/beacon/Identifier;
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public getIdentifier(I)Lorg/altbeacon/beacon/Identifier;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-le v0, p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lorg/altbeacon/beacon/Identifier;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return-object p0
.end method

.method public getIdentifiers()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public getUniqueId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hasSameIdentifiers(Lorg/altbeacon/beacon/Region;)Z
    .locals 4

    .line 1
    iget-object v0, p1, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 8
    .line 9
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x0

    .line 14
    if-ne v0, v1, :cond_5

    .line 15
    .line 16
    move v0, v2

    .line 17
    :goto_0
    iget-object v1, p1, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-ge v0, v1, :cond_4

    .line 24
    .line 25
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    return v2

    .line 38
    :cond_0
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    if-nez v1, :cond_1

    .line 49
    .line 50
    return v2

    .line 51
    :cond_1
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    if-nez v1, :cond_2

    .line 56
    .line 57
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    if-eqz v1, :cond_3

    .line 62
    .line 63
    :cond_2
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/Region;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    invoke-virtual {v1, v3}, Lorg/altbeacon/beacon/Identifier;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_3

    .line 76
    .line 77
    return v2

    .line 78
    :cond_3
    add-int/lit8 v0, v0, 0x1

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_4
    const/4 p0, 0x1

    .line 82
    return p0

    .line 83
    :cond_5
    return v2
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public matchesBeacon(Lorg/altbeacon/beacon/Beacon;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, v0, Lorg/altbeacon/beacon/BeaconParser;->mIdentifier:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getParserIdentifier()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    return v1

    .line 21
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 22
    .line 23
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    :cond_1
    add-int/lit8 v0, v0, -0x1

    .line 28
    .line 29
    if-ltz v0, :cond_5

    .line 30
    .line 31
    iget-object v2, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 32
    .line 33
    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Lorg/altbeacon/beacon/Identifier;

    .line 38
    .line 39
    iget-object v3, p1, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 40
    .line 41
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-ge v0, v3, :cond_2

    .line 46
    .line 47
    invoke-virtual {p1, v0}, Lorg/altbeacon/beacon/Beacon;->getIdentifier(I)Lorg/altbeacon/beacon/Identifier;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    const/4 v3, 0x0

    .line 53
    :goto_0
    if-nez v3, :cond_3

    .line 54
    .line 55
    if-nez v2, :cond_4

    .line 56
    .line 57
    :cond_3
    if-eqz v3, :cond_1

    .line 58
    .line 59
    if-eqz v2, :cond_1

    .line 60
    .line 61
    invoke-virtual {v2, v3}, Lorg/altbeacon/beacon/Identifier;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-nez v2, :cond_1

    .line 66
    .line 67
    :cond_4
    return v1

    .line 68
    :cond_5
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    .line 69
    .line 70
    if-eqz p0, :cond_6

    .line 71
    .line 72
    iget-object p1, p1, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    if-nez p0, :cond_6

    .line 79
    .line 80
    return v1

    .line 81
    :cond_6
    const/4 p0, 0x1

    .line 82
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 v1, 0x1

    .line 13
    move v2, v1

    .line 14
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-eqz v3, :cond_2

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast v3, Lorg/altbeacon/beacon/Identifier;

    .line 25
    .line 26
    if-le v2, v1, :cond_0

    .line 27
    .line 28
    const-string v4, " "

    .line 29
    .line 30
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    :cond_0
    const-string v4, "id"

    .line 34
    .line 35
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v4, ": "

    .line 42
    .line 43
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    if-nez v3, :cond_1

    .line 47
    .line 48
    const-string v3, "null"

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    invoke-virtual {v3}, Lorg/altbeacon/beacon/Identifier;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    :goto_1
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    add-int/lit8 v2, v2, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    iget-object p2, p0, Lorg/altbeacon/beacon/Region;->mUniqueId:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lorg/altbeacon/beacon/Region;->mBluetoothAddress:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 18
    .line 19
    .line 20
    iget-object p2, p0, Lorg/altbeacon/beacon/Region;->mIdentifiers:Ljava/util/List;

    .line 21
    .line 22
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v1, 0x0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Lorg/altbeacon/beacon/Identifier;

    .line 38
    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    invoke-virtual {v0}, Lorg/altbeacon/beacon/Identifier;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    iget-object p0, p0, Lorg/altbeacon/beacon/Region;->mBeaconParser:Lorg/altbeacon/beacon/BeaconParser;

    .line 54
    .line 55
    if-eqz p0, :cond_2

    .line 56
    .line 57
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconParser;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_2
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method

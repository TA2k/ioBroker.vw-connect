.class public final enum Lg61/m;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lg61/m;

.field public static final enum e:Lg61/m;

.field public static final synthetic f:[Lg61/m;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lg61/m;

    .line 2
    .line 3
    const-string v1, "PARKING_IN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lg61/m;

    .line 10
    .line 11
    const-string v2, "PARKING_OUT"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lg61/m;->d:Lg61/m;

    .line 18
    .line 19
    new-instance v2, Lg61/m;

    .line 20
    .line 21
    const-string v3, "PARKING_IN_OR_PARKING_OUT"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lg61/m;->e:Lg61/m;

    .line 28
    .line 29
    filled-new-array {v0, v1, v2}, [Lg61/m;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lg61/m;->f:[Lg61/m;

    .line 34
    .line 35
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lg61/m;
    .locals 1

    .line 1
    const-class v0, Lg61/m;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lg61/m;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lg61/m;
    .locals 1

    .line 1
    sget-object v0, Lg61/m;->f:[Lg61/m;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lg61/m;

    .line 8
    .line 9
    return-object v0
.end method

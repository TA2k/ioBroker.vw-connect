.class public final enum Lon0/y;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lon0/y;

.field public static final enum e:Lon0/y;

.field public static final synthetic f:[Lon0/y;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lon0/y;

    .line 2
    .line 3
    const-string v1, "Prepay"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lon0/y;->d:Lon0/y;

    .line 10
    .line 11
    new-instance v1, Lon0/y;

    .line 12
    .line 13
    const-string v2, "Postpay"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lon0/y;->e:Lon0/y;

    .line 20
    .line 21
    filled-new-array {v0, v1}, [Lon0/y;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lon0/y;->f:[Lon0/y;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lon0/y;
    .locals 1

    .line 1
    const-class v0, Lon0/y;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lon0/y;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lon0/y;
    .locals 1

    .line 1
    sget-object v0, Lon0/y;->f:[Lon0/y;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lon0/y;

    .line 8
    .line 9
    return-object v0
.end method

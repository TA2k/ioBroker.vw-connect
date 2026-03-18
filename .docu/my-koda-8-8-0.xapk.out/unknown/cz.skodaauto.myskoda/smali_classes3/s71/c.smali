.class public final enum Ls71/c;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Ls71/c;

.field public static final enum e:Ls71/c;

.field public static final synthetic f:[Ls71/c;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ls71/c;

    .line 2
    .line 3
    const-string v1, "USER_ACTION_REQUIRED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ls71/c;->d:Ls71/c;

    .line 10
    .line 11
    new-instance v1, Ls71/c;

    .line 12
    .line 13
    const-string v2, "WAITING_FOR_CHANGE_ON_VEHICLE"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Ls71/c;->e:Ls71/c;

    .line 20
    .line 21
    filled-new-array {v0, v1}, [Ls71/c;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Ls71/c;->f:[Ls71/c;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ls71/c;
    .locals 1

    .line 1
    const-class v0, Ls71/c;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ls71/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ls71/c;
    .locals 1

    .line 1
    sget-object v0, Ls71/c;->f:[Ls71/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ls71/c;

    .line 8
    .line 9
    return-object v0
.end method

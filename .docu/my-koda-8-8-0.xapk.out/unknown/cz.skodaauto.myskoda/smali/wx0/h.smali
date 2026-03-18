.class public final enum Lwx0/h;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lwx0/h;

.field public static final synthetic e:[Lwx0/h;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lwx0/h;

    .line 2
    .line 3
    const-string v1, "TOP_DOWN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lwx0/h;

    .line 10
    .line 11
    const-string v2, "BOTTOM_UP"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lwx0/h;->d:Lwx0/h;

    .line 18
    .line 19
    filled-new-array {v0, v1}, [Lwx0/h;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lwx0/h;->e:[Lwx0/h;

    .line 24
    .line 25
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lwx0/h;
    .locals 1

    .line 1
    const-class v0, Lwx0/h;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lwx0/h;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lwx0/h;
    .locals 1

    .line 1
    sget-object v0, Lwx0/h;->e:[Lwx0/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lwx0/h;

    .line 8
    .line 9
    return-object v0
.end method

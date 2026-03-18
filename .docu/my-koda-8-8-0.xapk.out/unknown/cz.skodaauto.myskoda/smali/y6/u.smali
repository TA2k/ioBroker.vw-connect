.class public final enum Ly6/u;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Ly6/u;

.field public static final synthetic e:[Ly6/u;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ly6/u;

    .line 2
    .line 3
    const-string v1, "Visible"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Ly6/u;->d:Ly6/u;

    .line 10
    .line 11
    new-instance v1, Ly6/u;

    .line 12
    .line 13
    const-string v2, "Invisible"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Ly6/u;

    .line 20
    .line 21
    const-string v3, "Gone"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    filled-new-array {v0, v1, v2}, [Ly6/u;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Ly6/u;->e:[Ly6/u;

    .line 32
    .line 33
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ly6/u;
    .locals 1

    .line 1
    const-class v0, Ly6/u;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ly6/u;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ly6/u;
    .locals 1

    .line 1
    sget-object v0, Ly6/u;->e:[Ly6/u;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ly6/u;

    .line 8
    .line 9
    return-object v0
.end method

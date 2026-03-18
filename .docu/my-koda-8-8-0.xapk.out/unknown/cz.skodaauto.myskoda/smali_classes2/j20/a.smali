.class public final enum Lj20/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic d:[Lj20/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lj20/a;

    .line 2
    .line 3
    const-string v1, "Mod"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    filled-new-array {v0}, [Lj20/a;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Lj20/a;->d:[Lj20/a;

    .line 14
    .line 15
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lj20/a;
    .locals 1

    .line 1
    const-class v0, Lj20/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lj20/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lj20/a;
    .locals 1

    .line 1
    sget-object v0, Lj20/a;->d:[Lj20/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lj20/a;

    .line 8
    .line 9
    return-object v0
.end method

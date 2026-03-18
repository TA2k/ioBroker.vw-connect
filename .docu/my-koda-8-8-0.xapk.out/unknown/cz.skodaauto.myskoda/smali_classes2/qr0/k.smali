.class public final enum Lqr0/k;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqr0/m;


# static fields
.field public static final enum d:Lqr0/k;

.field public static final enum e:Lqr0/k;

.field public static final synthetic f:[Lqr0/k;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lqr0/k;

    .line 2
    .line 3
    const-string v1, "Kilogram"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lqr0/k;->d:Lqr0/k;

    .line 10
    .line 11
    new-instance v1, Lqr0/k;

    .line 12
    .line 13
    const-string v2, "KilogramPer100Km"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lqr0/k;->e:Lqr0/k;

    .line 20
    .line 21
    filled-new-array {v0, v1}, [Lqr0/k;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lqr0/k;->f:[Lqr0/k;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqr0/k;
    .locals 1

    .line 1
    const-class v0, Lqr0/k;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqr0/k;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqr0/k;
    .locals 1

    .line 1
    sget-object v0, Lqr0/k;->f:[Lqr0/k;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqr0/k;

    .line 8
    .line 9
    return-object v0
.end method

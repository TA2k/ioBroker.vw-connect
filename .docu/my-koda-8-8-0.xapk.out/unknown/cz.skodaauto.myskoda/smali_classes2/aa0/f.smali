.class public final enum Laa0/f;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lgv/a;

.field public static final synthetic f:[Laa0/f;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Laa0/f;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "CHARGING"

    .line 5
    .line 6
    const-string v3, "Battery"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Laa0/f;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Laa0/f;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    const-string v3, "AIR_CONDITIONING"

    .line 15
    .line 16
    const-string v4, "ClimateControl"

    .line 17
    .line 18
    invoke-direct {v1, v4, v2, v3}, Laa0/f;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    filled-new-array {v0, v1}, [Laa0/f;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Laa0/f;->f:[Laa0/f;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    new-instance v0, Lgv/a;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Laa0/f;->e:Lgv/a;

    .line 37
    .line 38
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Laa0/f;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Laa0/f;
    .locals 1

    .line 1
    const-class v0, Laa0/f;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Laa0/f;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Laa0/f;
    .locals 1

    .line 1
    sget-object v0, Laa0/f;->f:[Laa0/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Laa0/f;

    .line 8
    .line 9
    return-object v0
.end method

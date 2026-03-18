.class public final enum Lce/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic e:[Lce/a;

.field public static final synthetic f:Lsx0/b;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lce/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "elli_remote"

    .line 5
    .line 6
    const-string v3, "App"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lce/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lce/a;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    const-string v3, "rfid"

    .line 15
    .line 16
    const-string v4, "Card"

    .line 17
    .line 18
    invoke-direct {v1, v4, v2, v3}, Lce/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v2, Lce/a;

    .line 22
    .line 23
    const/4 v3, 0x2

    .line 24
    const-string v4, "plug_and_charge"

    .line 25
    .line 26
    const-string v5, "PlugAndCharge"

    .line 27
    .line 28
    invoke-direct {v2, v5, v3, v4}, Lce/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    filled-new-array {v0, v1, v2}, [Lce/a;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lce/a;->e:[Lce/a;

    .line 36
    .line 37
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lce/a;->f:Lsx0/b;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lce/a;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lce/a;
    .locals 1

    .line 1
    const-class v0, Lce/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lce/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lce/a;
    .locals 1

    .line 1
    sget-object v0, Lce/a;->e:[Lce/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lce/a;

    .line 8
    .line 9
    return-object v0
.end method

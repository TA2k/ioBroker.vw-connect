.class public final enum Lmz/h;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum f:Lmz/h;

.field public static final enum g:Lmz/h;

.field public static final enum h:Lmz/h;

.field public static final synthetic i:[Lmz/h;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lmz/h;

    .line 2
    .line 3
    const-string v1, "auxiliary-heating"

    .line 4
    .line 5
    const-string v2, "start-stop-auxiliary-heating"

    .line 6
    .line 7
    const-string v3, "AuxiliaryHeating"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v3, v4, v1, v2}, Lmz/h;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lmz/h;->f:Lmz/h;

    .line 14
    .line 15
    new-instance v1, Lmz/h;

    .line 16
    .line 17
    const-string v2, "climate-plans"

    .line 18
    .line 19
    const-string v3, "set-climate-plans"

    .line 20
    .line 21
    const-string v4, "PlansRequest"

    .line 22
    .line 23
    const/4 v5, 0x1

    .line 24
    invoke-direct {v1, v4, v5, v2, v3}, Lmz/h;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    sput-object v1, Lmz/h;->g:Lmz/h;

    .line 28
    .line 29
    new-instance v2, Lmz/h;

    .line 30
    .line 31
    const-string v3, "air-conditioning"

    .line 32
    .line 33
    const-string v4, "set-target-temperature"

    .line 34
    .line 35
    const-string v5, "SetTargetTemperature"

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    invoke-direct {v2, v5, v6, v3, v4}, Lmz/h;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    sput-object v2, Lmz/h;->h:Lmz/h;

    .line 42
    .line 43
    filled-new-array {v0, v1, v2}, [Lmz/h;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lmz/h;->i:[Lmz/h;

    .line 48
    .line 49
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lmz/h;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p4, p0, Lmz/h;->e:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lmz/h;
    .locals 1

    .line 1
    const-class v0, Lmz/h;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lmz/h;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lmz/h;
    .locals 1

    .line 1
    sget-object v0, Lmz/h;->i:[Lmz/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lmz/h;

    .line 8
    .line 9
    return-object v0
.end method
